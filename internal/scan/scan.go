// Package scan recorre un repositorio SIN EJECUTAR NADA y junta señales de riesgo: reglas por linea,
// binarios, codigo escondido, Unicode enganoso, scripts de instalacion y tareas del editor. Al final
// cruza señales del mismo archivo (por ejemplo, leer credenciales y enviarlas afuera).
package scan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/ulisespignatelli/repoguard/internal/finding"
	"github.com/ulisespignatelli/repoguard/internal/rules"
)

// Options controla el escaneo.
type Options struct {
	MaxBytes int64
	Workers  int
	Exclude  []string
}

// Result es el resultado de un escaneo.
type Result struct {
	Files    int               `json:"files_scanned"`
	Findings []finding.Finding `json:"findings"`
	Verdict  finding.Verdict   `json:"verdict"`
}

var skipDirs = map[string]bool{".git": true, "node_modules": true, ".venv": true, "venv": true, "__pycache__": true}

var mediaExt = map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".ico": true,
	".svg": true, ".pdf": true, ".mp4": true, ".mp3": true, ".woff": true, ".woff2": true, ".ttf": true, ".otf": true}

var binExt = map[string]bool{".exe": true, ".dll": true, ".so": true, ".dylib": true, ".jar": true, ".bin": true,
	".msi": true, ".scr": true, ".apk": true, ".com": true, ".sys": true, ".elf": true, ".pyc": true, ".class": true}

var codeExt = map[string]bool{".py": true, ".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".sh": true,
	".bash": true, ".zsh": true, ".ps1": true, ".psm1": true, ".bat": true, ".cmd": true, ".vbs": true, ".rb": true,
	".php": true, ".go": true, ".pl": true, ".lua": true}

var suspiciousName = regexp.MustCompile(`(?i)(crack|keygen|loader|activator|patcher|inject|stealer|grabber|rat\b|payload)`)

// Scan analiza la carpeta root. Las rutas del informe son relativas a root.
func Scan(root string, opt Options) (Result, error) {
	if opt.Workers <= 0 {
		opt.Workers = 8
	}
	if opt.MaxBytes <= 0 {
		opt.MaxBytes = 5 << 20
	}
	lineRules := rules.All()
	paths := make(chan string, 256)
	var (
		mu    sync.Mutex
		out   []finding.Finding
		files int
		wg    sync.WaitGroup
	)
	for range opt.Workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range paths {
				rel, _ := filepath.Rel(root, p)
				rel = filepath.ToSlash(rel)
				fs := analyzeFile(p, rel, lineRules, opt.MaxBytes)
				mu.Lock()
				out = append(out, fs...)
				files++
				mu.Unlock()
			}
		}()
	}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			if p != root && (skipDirs[d.Name()] || excluded(rel, opt.Exclude)) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			mu.Lock()
			out = append(out, symlinkFinding(p, filepath.ToSlash(rel)))
			mu.Unlock()
			return nil
		}
		if !d.Type().IsRegular() || excluded(rel, opt.Exclude) || mediaExt[strings.ToLower(filepath.Ext(p))] {
			return nil
		}
		paths <- p
		return nil
	})
	close(paths)
	wg.Wait()
	out = adjustForContext(out)
	sortFindings(out)
	return Result{Files: files, Findings: out, Verdict: finding.Decide(out)}, err
}

func mk(r rules.Rule, file string, line int, text string) finding.Finding {
	return finding.Finding{RuleID: r.ID, Category: r.Category, Title: r.Title, Severity: r.Severity,
		File: file, Line: line, Evidence: finding.Evidence(text), Why: r.Why}
}

func custom(id, cat, title string, sev finding.Severity, file string, line int, ev, why string) finding.Finding {
	return finding.Finding{RuleID: id, Category: cat, Title: title, Severity: sev, File: file, Line: line,
		Evidence: finding.Evidence(ev), Why: why}
}

func analyzeFile(path, rel string, lineRules []rules.Rule, maxBytes int64) []finding.Finding {
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	ext := strings.ToLower(filepath.Ext(rel))
	base := strings.ToLower(filepath.Base(rel))
	if info.Size() > maxBytes {
		if binExt[ext] {
			return []finding.Finding{binaryFinding(rel, ext)}
		}
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if kind := binaryKind(data, ext); kind != "" {
		return []finding.Finding{binaryFinding(rel, kind)}
	}

	var out []finding.Finding
	switch {
	case base == "package.json":
		out = append(out, packageJSON(rel, data)...)
	case base == "setup.py":
		out = append(out, setupPy(rel, data)...)
	case strings.HasSuffix(filepath.ToSlash(rel), ".vscode/tasks.json"):
		out = append(out, vscodeTasks(rel, data)...)
	case strings.Contains(filepath.ToSlash(rel), ".devcontainer/") && ext == ".json":
		out = append(out, devcontainer(rel, data)...)
	}
	isReq := strings.HasPrefix(base, "requirements") && ext == ".txt"
	slash := "/" + filepath.ToSlash(rel)
	minified := strings.Contains(base, ".min.") || strings.Contains(slash, "/dist/") || strings.Contains(slash, "/build/")

	markdown := ext == ".md" || ext == ".markdown" || ext == ".rst"
	ciFile := strings.Contains(slash, "/.github/workflows/") || strings.Contains(slash, "/.gitlab-ci") ||
		strings.Contains(slash, "/.circleci/")
	dockerfile := strings.HasPrefix(base, "dockerfile") || strings.HasSuffix(base, ".dockerfile") || base == "containerfile"
	inFence := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		low := strings.ToLower(line)
		if markdown && (strings.HasPrefix(strings.TrimSpace(line), "```") || strings.HasPrefix(strings.TrimSpace(line), "~~~")) {
			inFence = !inFence
			continue
		}
		if codeExt[ext] && !minified {
			if f, ok := hiddenCode(rel, n, line); ok {
				out = append(out, f)
			}
			if len(line) > 2000 {
				out = append(out, custom("long-line", rules.CatObfuscation, "Línea de código extremadamente larga",
					finding.Medium, rel, n, line, "Código de una sola línea gigante suele ser código ofuscado o una carga empaquetada."))
			}
			if m := blobRe.FindString(line); len(m) >= 400 {
				out = append(out, custom("encoded-blob", rules.CatObfuscation, "Bloque grande de datos codificados en el código",
					finding.Medium, rel, n, line, "Puede ser un recurso legítimo o una carga oculta; revisá qué se hace con él."))
			}
		}
		if f, ok := unicodeTricks(rel, n, line); ok {
			out = append(out, f)
		}
		// En documentacion solo importan los bloques de comandos (lo que el lector copia y pega), no la prosa.
		if len(line) > 20000 || (markdown && !inFence) {
			continue
		}
		for _, r := range lineRules {
			if r.ID == "dep-remote" && !isReq {
				continue
			}
			if !hasAny(low, r.Keywords) {
				continue
			}
			m := r.Pattern.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			if r.ID == "raw-ip-url" && !publicIP(m[1]) {
				continue
			}
			f := mk(r, rel, n, line)
			switch {
			case markdown:
				f.Severity = max(finding.Low, min(f.Severity-1, finding.Medium))
				f.Title = "La documentación pide: " + lowerFirst(f.Title)
			case isComment(line, ext):
				f.Severity = finding.Low
				f.Title = "En un comentario: " + lowerFirst(f.Title)
				f.Why = "Aparece en un comentario, no en código que se ejecuta. " + f.Why
			case ciFile:
				f.Severity = max(finding.Low, f.Severity-2)
				f.Why = "Está en un workflow de CI: se ejecuta en los servidores de GitHub, no en tu máquina. " + f.Why
			case dockerfile:
				f.Severity = max(finding.Low, f.Severity-1)
				f.Why = "Está en un Dockerfile: afecta la imagen del contenedor, no tu sistema directamente. " + f.Why
			}
			// Nombrar una ruta (en una lista, un comentario o un mensaje) no es leerla: sin una operacion de
			// acceso en la misma linea, la señal baja a "menciona".
			if r.Category == rules.CatCreds && r.ID != "env-dump" && !accessCtx.MatchString(line) {
				f.Severity, f.Title = finding.Low, "Menciona: "+strings.ToLower(f.Title[:1])+f.Title[1:]
				f.Why = "La ruta aparece en el texto, pero no se ve una operación de lectura en esa línea. " + f.Why
			}
			out = append(out, f)
		}
	}
	return correlate(rel, out)
}

var blobRe = regexp.MustCompile(`[A-Za-z0-9+/=]{400,}`)

func lowerFirst(s string) string { return strings.ToLower(s[:1]) + s[1:] }

// isComment reconoce lineas que son solo comentario (sin contar el shebang).
func isComment(line, ext string) bool {
	t := strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(t, "#!"):
		return false
	case strings.HasPrefix(t, "#"):
		return ext != ".md"
	case strings.HasPrefix(t, "//"), strings.HasPrefix(t, "/*"), strings.HasPrefix(t, "* "), strings.HasPrefix(t, "<!--"):
		return true
	case strings.HasPrefix(t, "--") && (ext == ".lua" || ext == ".sql"):
		return true
	case (strings.HasPrefix(strings.ToLower(t), "rem ") || strings.HasPrefix(t, "::")) && (ext == ".bat" || ext == ".cmd"):
		return true
	}
	return false
}

// accessCtx son operaciones que leen, copian o abren archivos (o arman rutas al directorio del usuario).
var accessCtx = regexp.MustCompile(`(?i)\b(open|read|readfile|readfilesync|read_text|read_bytes|load|expanduser|expandvars|homedir|path\.join|os\.path|pathlib|path\(|glob|walk|copy|copyfile|shutil|cat|cp|scp|tar|zip|get-content|gc|type|readalltext|file\.|fs\.|ioutil|os\.readfile|getenv\(.?(home|userprofile|appdata|localappdata))\b|~[/\\]|\$home|%userprofile%|%appdata%|%localappdata%|\$env:(userprofile|appdata|localappdata)`)

func hasAny(low string, kws []string) bool {
	for _, k := range kws {
		if strings.Contains(low, k) {
			return true
		}
	}
	return len(kws) == 0
}

func publicIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.Equal(net.ParseIP("169.254.169.254")) || strings.HasPrefix(s, "192.0.2.") ||
		strings.HasPrefix(s, "198.51.100.") || strings.HasPrefix(s, "203.0.113.") || ip.IsMulticast())
}

// hiddenCode detecta codigo empujado fuera de la pantalla con cientos de espacios.
func hiddenCode(rel string, n int, line string) (finding.Finding, bool) {
	trimmed := strings.TrimLeft(line, " \t")
	if lead := len(line) - len(trimmed); lead >= 150 && trimmed != "" {
		return custom("hidden-indent", rules.CatObfuscation, "Código escondido fuera de la pantalla", finding.High, rel, n,
			trimmed, "Hay código precedido por cientos de espacios para que no se vea al abrir el archivo."), true
	}
	if i := strings.Index(line, strings.Repeat(" ", 150)); i > 0 {
		if rest := strings.TrimSpace(line[i:]); rest != "" && strings.TrimSpace(line[:i]) != "" {
			return custom("hidden-trailing", rules.CatObfuscation, "Código escondido a la derecha de una línea normal",
				finding.High, rel, n, rest, "Después de una línea de aspecto normal hay cientos de espacios y más código: un truco para ocultarlo en el editor."), true
		}
	}
	return finding.Finding{}, false
}

// unicodeTricks detecta caracteres de control bidireccional (Trojan Source) e invisibles.
func unicodeTricks(rel string, n int, line string) (finding.Finding, bool) {
	for i, r := range line {
		switch {
		case (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069):
			return custom("bidi-control", rules.CatUnicode, "Caracteres que invierten el orden del texto (Trojan Source)",
				finding.High, rel, n, strings.Map(visible, line),
				"El código que ves no es el que ejecuta el compilador o el intérprete (CVE-2021-42574)."), true
		case r == 0x200B || r == 0x200C || r == 0x200D || r == 0x2060 || (r == 0xFEFF && !(n == 1 && i == 0)):
			return custom("invisible-char", rules.CatUnicode, "Caracter invisible dentro del texto", finding.Medium, rel, n,
				strings.Map(visible, line), "Los caracteres invisibles pueden hacer que dos nombres parezcan iguales sin serlo."), true
		}
	}
	return finding.Finding{}, false
}

func visible(r rune) rune {
	if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200B || r == 0x200C || r == 0x200D ||
		r == 0x2060 || r == 0xFEFF {
		return '⟦'
	}
	return r
}

func binaryKind(data []byte, ext string) string {
	switch {
	case bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}):
		return "ELF (Linux)"
	case bytes.HasPrefix(data, []byte("MZ")) && len(data) > 0x40:
		return "PE (Windows)"
	case bytes.HasPrefix(data, []byte{0xcf, 0xfa, 0xed, 0xfe}) || bytes.HasPrefix(data, []byte{0xfe, 0xed, 0xfa, 0xcf}):
		return "Mach-O (macOS)"
	case bytes.HasPrefix(data, []byte{0xca, 0xfe, 0xba, 0xbe}):
		return "Java/Mach-O universal"
	case bytes.HasPrefix(data, []byte("PK\x03\x04")) && (ext == ".jar" || ext == ".apk"):
		return strings.TrimPrefix(ext, ".")
	case binExt[ext] && bytes.IndexByte(data[:min(len(data), 8000)], 0) >= 0:
		return strings.TrimPrefix(ext, ".")
	}
	return ""
}

func binaryFinding(rel, kind string) finding.Finding {
	sev, why := finding.Medium, "No se puede revisar qué hace sin ingeniería inversa. Preferí compilarlo desde su código fuente."
	if suspiciousName.MatchString(filepath.Base(rel)) {
		sev, why = finding.High, "Ejecutable sin código fuente con un nombre típico de cracks o cargadores, muy usados para distribuir malware."
	}
	return custom("binary", rules.CatBinary, "Ejecutable incluido sin código fuente ("+kind+")", sev, rel, 0, "", why)
}

func symlinkFinding(path, rel string) finding.Finding {
	target, _ := os.Readlink(path)
	sev := finding.Low
	if filepath.IsAbs(target) || strings.Contains(target, "..") {
		sev = finding.Medium
	}
	return custom("symlink", rules.CatSupply, "Enlace simbólico", sev, rel, 0, "→ "+target,
		"Un enlace que apunta fuera del repo puede hacer que una herramienta lea o escriba archivos de tu sistema.")
}

var installNet = regexp.MustCompile(`(?i)\b(curl|wget|node\s+-e|powershell|iwr|invoke-webrequest|base64|eval|https?://|bash\s+-c|sh\s+-c)`)

func packageJSON(rel string, data []byte) []finding.Finding {
	var pkg struct {
		Scripts         map[string]string `json:"scripts"`
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return nil
	}
	var out []finding.Finding
	hooks := []string{"preinstall", "install", "postinstall", "prepare", "preuninstall", "postuninstall"}
	for _, h := range hooks {
		cmd, ok := pkg.Scripts[h]
		if !ok {
			continue
		}
		if installNet.MatchString(cmd) {
			out = append(out, custom("npm-install-hook", rules.CatInstall, "Script de npm que descarga o ejecuta código al instalar",
				finding.High, rel, 0, h+": "+cmd, "Corre automáticamente con `npm install`, antes de que uses la herramienta."))
		} else {
			out = append(out, custom("npm-install-hook", rules.CatInstall, "Script de npm que corre al instalar", finding.Low,
				rel, 0, h+": "+cmd, "Se ejecuta solo con `npm install`. Revisá el archivo que llama."))
		}
	}
	for name, v := range merge(pkg.Dependencies, pkg.DevDependencies) {
		if strings.HasPrefix(v, "http") || strings.HasPrefix(v, "git") || strings.HasPrefix(v, "github:") || strings.Contains(v, "/") && !strings.HasPrefix(v, "npm:") && !strings.HasPrefix(v, "workspace:") && !strings.HasPrefix(v, "file:") {
			out = append(out, custom("npm-remote-dep", rules.CatSupply, "Dependencia de npm desde una URL o un repo git",
				finding.Medium, rel, 0, name+": "+v, "No pasa por el registro de npm: el contenido puede cambiar sin versión."))
		}
	}
	return out
}

func merge(a, b map[string]string) map[string]string {
	m := map[string]string{}
	for k, v := range a {
		m[k] = v
	}
	for k, v := range b {
		m[k] = v
	}
	return m
}

var setupExec = regexp.MustCompile(`(?i)\b(os\.system|subprocess\.|urllib\.request|requests\.(get|post)|socket\.socket|exec\(|eval\()`)

func setupPy(rel string, data []byte) []finding.Finding {
	var out []finding.Finding
	for i, line := range strings.Split(string(data), "\n") {
		if setupExec.MatchString(line) {
			out = append(out, custom("setup-py-exec", rules.CatInstall, "setup.py ejecuta código o se conecta a la red al instalar",
				finding.High, rel, i+1, line, "`pip install` ejecuta setup.py: un instalador no debería lanzar comandos ni descargar cosas."))
		}
	}
	return out
}

func vscodeTasks(rel string, data []byte) []finding.Finding {
	if bytes.Contains(bytes.ReplaceAll(data, []byte(" "), nil), []byte(`"runOn":"folderOpen"`)) {
		return []finding.Finding{custom("vscode-autorun", rules.CatEditor, "VS Code ejecuta una tarea al abrir la carpeta",
			finding.High, rel, 0, `"runOn": "folderOpen"`,
			"Con solo abrir el repo en VS Code (si aceptás confiar en la carpeta) se ejecuta un comando. Es un vector conocido contra desarrolladores.")}
	}
	return nil
}

func devcontainer(rel string, data []byte) []finding.Finding {
	var out []finding.Finding
	for i, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "Command") && installNet.MatchString(line) {
			out = append(out, custom("devcontainer-cmd", rules.CatInstall, "El devcontainer descarga o ejecuta código al crearse",
				finding.Medium, rel, i+1, line, "Se ejecuta al abrir el proyecto en un contenedor de desarrollo."))
		}
	}
	return out
}

// correlate sube la gravedad cuando un mismo archivo lee credenciales y además envía datos afuera.
func correlate(rel string, fs []finding.Finding) []finding.Finding {
	var creds, exfil *finding.Finding
	for i := range fs {
		switch fs[i].Category {
		case rules.CatCreds:
			if creds == nil && fs[i].Severity >= finding.Medium { // solo accesos reales, no menciones
				creds = &fs[i]
			}
		case rules.CatExfil:
			if exfil == nil {
				exfil = &fs[i]
			}
		}
	}
	if creds == nil || exfil == nil {
		return fs
	}
	return append(fs, custom("steal-and-send", rules.CatCorrelation, "Posible robo de datos: accede a credenciales y envía información afuera",
		finding.Critical, rel, creds.Line, creds.Title+" (línea "+itoa(creds.Line)+") + "+strings.ToLower(exfil.Title)+" (línea "+itoa(exfil.Line)+")",
		"La combinación de las dos cosas en el mismo archivo es el patrón de un ladrón de credenciales."))
}

func itoa(n int) string { return strconv.Itoa(n) }

// docHints son rutas donde una señal suele ser documentacion o un ejemplo, no codigo que se ejecuta.
var docHints = []string{"test", "spec", "fixture", "example", "sample", "docs/", "testdata"}

// adjustForContext baja un nivel las señales en documentacion y pruebas (nunca las de binarios ni Unicode).
func adjustForContext(fs []finding.Finding) []finding.Finding {
	for i := range fs {
		f := &fs[i]
		p := strings.ToLower(f.File)
		doc := strings.HasSuffix(p, ".txt") && !strings.Contains(p, "requirements")
		for _, h := range docHints {
			if strings.Contains(p, h) {
				doc = true
			}
		}
		if strings.HasPrefix(f.Title, "La documentación pide") {
			doc = false // ya se ajustó al leer el Markdown
		}
		if doc && f.Category != rules.CatBinary && f.Category != rules.CatUnicode && f.Severity > finding.Low {
			f.Severity--
			f.Why += " (Aparece en documentación o pruebas: por eso tiene un nivel menos.)"
		}
		f.SeverityStr = f.Severity.String()
	}
	return fs
}

func sortFindings(fs []finding.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		return fs[i].Line < fs[j].Line
	})
}

func excluded(rel string, patterns []string) bool {
	rel = filepath.ToSlash(rel)
	for _, p := range patterns {
		if ok, _ := filepath.Match(p, rel); ok {
			return true
		}
		if ok, _ := filepath.Match(p, filepath.Base(rel)); ok {
			return true
		}
		if strings.HasSuffix(p, "/**") && strings.HasPrefix(rel, strings.TrimSuffix(p, "**")) {
			return true
		}
	}
	return false
}
