// repoguard revisa un repositorio ANTES de ejecutarlo y avisa si tiene señales de malware: descarga y
// ejecucion de codigo, ofuscacion, robo de credenciales, envio de datos, persistencia o binarios sin fuente.
// Nunca ejecuta el codigo que analiza. Solo usa la biblioteca estandar de Go.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ulisespignatelli/repoguard/internal/finding"
	"github.com/ulisespignatelli/repoguard/internal/remote"
	"github.com/ulisespignatelli/repoguard/internal/report"
	"github.com/ulisespignatelli/repoguard/internal/scan"
)

var version = "dev"

const usage = `repoguard: revisá un repositorio antes de ejecutarlo.

Uso:
  repoguard scan RUTA                     una carpeta local
  repoguard scan duenio/repo              un repo de GitHub (se clona en una carpeta temporal y se borra)
  repoguard scan https://github.com/duenio/repo
  repoguard version

Opciones:
  --format FORMATO        text (por defecto), json o sarif
  --output ARCHIVO        escribe el informe en un archivo
  --min-severity NIVEL    muestra desde este nivel: info, baja, media (por defecto), alta, critica
  --fail-on NIVEL         sale con código 1 si hay señales desde este nivel (por defecto alta)
  --exclude PATRONES      globs separados por coma

repoguard nunca ejecuta el código que revisa. Que no encuentre señales no garantiza que algo sea seguro.
Códigos de salida: 0 sin señales desde --fail-on, 1 con señales, 2 error.
`

// cloneFunc se reemplaza en los tests.
var cloneFunc = remote.Clone

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "scan":
		return scanCmd(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "repoguard", version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "comando desconocido: %q\n\n%s", args[0], usage)
	return 2
}

func scanCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	format := fs.String("format", "text", "")
	output := fs.String("output", "", "")
	minSev := fs.String("min-severity", "media", "")
	failOn := fs.String("fail-on", "alta", "")
	exclude := fs.String("exclude", "", "")
	var pos []string
	for rest := args; ; {
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if len(pos) != 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	min, ok1 := finding.ParseSeverity(*minSev)
	fail, ok2 := finding.ParseSeverity(*failOn)
	if !ok1 || !ok2 || (*format != "text" && *format != "json" && *format != "sarif") {
		fmt.Fprintln(stderr, "opciones inválidas: revisá --format, --min-severity y --fail-on")
		return 2
	}

	target := pos[0]
	meta := report.Meta{Target: target, Version: version}
	root := target
	if _, err := os.Stat(target); err != nil {
		r, ok := remote.ParseRepo(target)
		if !ok {
			fmt.Fprintf(stderr, "error: %q no es una carpeta ni un repo de GitHub (duenio/repo o URL)\n", target)
			return 2
		}
		fmt.Fprintf(stderr, "Clonando %s en una carpeta temporal (no se ejecuta nada)…\n", r.FullName())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		dir, cleanup, err := cloneFunc(ctx, r, remote.Token())
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		defer cleanup()
		root, meta.Target, meta.URL = dir, r.FullName(), "https://github.com/"+r.FullName()
	}

	res, err := scan.Scan(root, scan.Options{Exclude: split(*exclude)})
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	var shown []finding.Finding
	for _, f := range res.Findings {
		if f.Severity >= min {
			shown = append(shown, f)
		}
	}

	w := stdout
	if *output != "" {
		f, err := os.OpenFile(*output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		defer f.Close()
		w = f
	}
	switch *format {
	case "json":
		err = report.JSON(w, res, meta)
	case "sarif":
		err = report.SARIF(w, res, meta)
	default:
		report.Text(w, res, shown, meta, w == stdout && terminal(stdout))
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	for _, f := range res.Findings {
		if f.Severity >= fail {
			return 1
		}
	}
	return 0
}

func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func terminal(w io.Writer) bool {
	if os.Getenv("FORCE_COLOR") != "" {
		return true
	}
	f, ok := w.(*os.File)
	if !ok || os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
