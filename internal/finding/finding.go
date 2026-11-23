// Package finding define una señal encontrada en un repositorio y el veredicto final.
package finding

import (
	"regexp"
	"strings"
)

// Severity ordena la gravedad de una señal.
type Severity int

const (
	Info Severity = iota + 1
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	return map[Severity]string{Critical: "crítica", High: "alta", Medium: "media", Low: "baja", Info: "info"}[s]
}

// ParseSeverity acepta nombres en castellano o en ingles.
func ParseSeverity(v string) (Severity, bool) {
	switch strings.ToLower(v) {
	case "critica", "crítica", "critical":
		return Critical, true
	case "alta", "high":
		return High, true
	case "media", "medium":
		return Medium, true
	case "baja", "low":
		return Low, true
	case "info":
		return Info, true
	}
	return 0, false
}

// Finding es una señal de riesgo con su evidencia.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Severity    Severity `json:"-"`
	SeverityStr string   `json:"severity"`
	File        string   `json:"file"`
	Line        int      `json:"line,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	Why         string   `json:"why"`
}

// Verdict resume el riesgo de ejecutar el repositorio.
type Verdict struct {
	Level   string `json:"level"`   // no_ejecutar | revisar | precaucion | sin_senales
	Label   string `json:"label"`   // texto para la terminal
	Summary string `json:"summary"` // por que
}

// Decide arma el veredicto a partir de la señal mas grave.
func Decide(fs []Finding) Verdict {
	top := Severity(0)
	for _, f := range fs {
		top = max(top, f.Severity)
	}
	switch {
	case top >= Critical:
		return Verdict{"no_ejecutar", "NO EJECUTAR", "hay señales fuertes de comportamiento malicioso; no lo instales ni lo corras"}
	case top >= High:
		return Verdict{"revisar", "REVISAR A MANO ANTES DE EJECUTAR", "hay comportamientos de riesgo que pueden ser legítimos o no; leé cada evidencia"}
	case top >= Medium:
		return Verdict{"precaucion", "PRECAUCIÓN", "nada claramente malicioso, pero hay prácticas riesgosas; ejecutalo aislado"}
	default:
		return Verdict{"sin_senales", "SIN SEÑALES DE RIESGO", "no se encontraron señales conocidas; eso no garantiza que sea seguro"}
	}
}

var (
	webhookTail  = regexp.MustCompile(`(webhooks/\d+/)[A-Za-z0-9_-]{6,}`)
	telegramTok  = regexp.MustCompile(`(bot\d{6,})(:[A-Za-z0-9_-]{6,})`)
	longB64      = regexp.MustCompile(`[A-Za-z0-9+/=]{80,}`)
	spaceRuns    = regexp.MustCompile(`\s{4,}`)
	maxEvidence  = 160
	ellipsisChar = "…"
)

// Evidence recorta la linea para mostrarla sin desbordar la terminal ni repetir credenciales ajenas.
func Evidence(line string) string {
	s := strings.TrimSpace(line)
	s = spaceRuns.ReplaceAllString(s, " ")
	s = webhookTail.ReplaceAllString(s, "${1}****")
	s = telegramTok.ReplaceAllString(s, "${1}:****")
	s = longB64.ReplaceAllStringFunc(s, func(m string) string { return m[:24] + ellipsisChar + "(" + itoa(len(m)) + " caracteres)" })
	if r := []rune(s); len(r) > maxEvidence {
		s = string(r[:maxEvidence]) + ellipsisChar
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
