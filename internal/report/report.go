// Package report escribe el resultado en texto, JSON o SARIF 2.1.0.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ulisespignatelli/repoguard/internal/finding"
	"github.com/ulisespignatelli/repoguard/internal/scan"
)

// Meta describe que se escaneo.
type Meta struct {
	Target  string `json:"target"`
	URL     string `json:"url,omitempty"` // base para enlazar a GitHub
	Version string `json:"version"`
}

var label = map[finding.Severity]string{finding.Critical: "CRÍTICA", finding.High: "ALTA   ", finding.Medium: "MEDIA  ",
	finding.Low: "BAJA   ", finding.Info: "INFO   "}
var color = map[finding.Severity]string{finding.Critical: "1;31", finding.High: "31", finding.Medium: "33",
	finding.Low: "36", finding.Info: "2"}

// Text escribe el informe para la terminal.
func Text(w io.Writer, r scan.Result, shown []finding.Finding, m Meta, useColor bool) {
	c := func(code, t string) string {
		if !useColor {
			return t
		}
		return "\x1b[" + code + "m" + t + "\x1b[0m"
	}
	fmt.Fprintf(w, "%s %s · %s · %d archivos revisados (sin ejecutar nada)\n", c("1", "repoguard"), m.Version, m.Target, r.Files)
	// Agrupa la misma señal repetida en un archivo: una entrada con todas las lineas.
	type group struct {
		f     finding.Finding
		lines []int
	}
	var groups []*group
	idx := map[string]*group{}
	for _, f := range shown {
		k := f.RuleID + "\x00" + f.File + "\x00" + f.Title
		if g, ok := idx[k]; ok {
			g.lines = append(g.lines, f.Line)
			continue
		}
		g := &group{f: f, lines: []int{f.Line}}
		idx[k] = g
		groups = append(groups, g)
	}
	for _, g := range groups {
		f := g.f
		loc := f.File
		if f.Line > 0 {
			nums := make([]string, 0, len(g.lines))
			for _, l := range g.lines[:min(len(g.lines), 8)] {
				nums = append(nums, fmt.Sprint(l))
			}
			loc = f.File + ":" + strings.Join(nums, ", ")
			if len(g.lines) > 8 {
				loc += fmt.Sprintf(" y %d más", len(g.lines)-8)
			}
		}
		fmt.Fprintf(w, "\n%s %s  %s\n", c(color[f.Severity], "["+label[f.Severity]+"]"), f.Title, c("2", "("+f.Category+")"))
		fmt.Fprintf(w, "    %s %s\n", c("2", "dónde:    "), loc)
		if f.Evidence != "" {
			fmt.Fprintf(w, "    %s %s\n", c("2", "evidencia:"), f.Evidence)
		}
		fmt.Fprintf(w, "    %s %s\n", c("2", "por qué:  "), f.Why)
	}
	if hidden := len(r.Findings) - len(shown); hidden > 0 {
		fmt.Fprintf(w, "\n%s\n", c("2", fmt.Sprintf("(%d señal(es) de menor gravedad ocultas por --min-severity)", hidden)))
	}
	count := map[finding.Severity]int{}
	for _, f := range r.Findings {
		count[f.Severity]++
	}
	vc := map[string]string{"no_ejecutar": "1;31", "revisar": "1;33", "precaucion": "33", "sin_senales": "1;32"}[r.Verdict.Level]
	fmt.Fprintf(w, "\nSeñales: %d crítica(s), %d alta(s), %d media(s), %d baja(s)\n",
		count[finding.Critical], count[finding.High], count[finding.Medium], count[finding.Low])
	fmt.Fprintf(w, "Veredicto: %s — %s.\n", c(vc, r.Verdict.Label), r.Verdict.Summary)
	if r.Verdict.Level != "sin_senales" {
		fmt.Fprintln(w, c("2", "Si igual lo vas a probar, hacelo en una máquina virtual descartable, sin tus credenciales."))
	}
}

// JSON escribe el resultado completo.
func JSON(w io.Writer, r scan.Result, m Meta) error {
	if r.Findings == nil {
		r.Findings = []finding.Finding{}
	}
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(map[string]any{"target": m, "result": r})
}

// SARIF escribe un informe SARIF 2.1.0 (pestaña Security de GitHub y otros visores).
func SARIF(w io.Writer, r scan.Result, m Meta) error {
	level := map[finding.Severity]string{finding.Critical: "error", finding.High: "error", finding.Medium: "warning",
		finding.Low: "note", finding.Info: "note"}
	seen := map[string]bool{}
	var ruleDefs []map[string]any
	results := make([]map[string]any, 0, len(r.Findings))
	for _, f := range r.Findings {
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			ruleDefs = append(ruleDefs, map[string]any{"id": f.RuleID, "shortDescription": map[string]string{"text": f.Title},
				"properties": map[string]any{"tags": []string{"security", "supply-chain", f.Category}}})
		}
		region := map[string]int{"startLine": max(1, f.Line)}
		results = append(results, map[string]any{
			"ruleId": f.RuleID, "level": level[f.Severity],
			"message": map[string]string{"text": strings.TrimSpace(f.Title + ". " + f.Why + " " + f.Evidence)},
			"locations": []any{map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]string{"uri": f.File}, "region": region}}},
		})
	}
	doc := map[string]any{"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{"name": "repoguard", "version": m.Version,
				"informationUri": "https://github.com/ulisespignatelli/repoguard", "rules": ruleDefs}},
			"results": results}}}
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(doc)
}
