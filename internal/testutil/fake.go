// Package testutil arma secretos FALSOS en tiempo de ejecucion. Se concatenan partes para que el
// propio repositorio no contenga cadenas con forma de secreto (y no lo marquen otros escaneres).
package testutil

import "strings"

// J une partes: J("gh", "p_", ...) evita escribir el token completo en el codigo.
func J(parts ...string) string { return strings.Join(parts, "") }

// Rand devuelve una cadena pseudoaleatoria y determinista del alfabeto dado.
func Rand(n int, alphabet string, seed int) string {
	b := make([]byte, n)
	x := uint32(seed*2654435761 + 1)
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b[i] = alphabet[int(x)%len(alphabet)]
	}
	return string(b)
}

const (
	Alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	Hex   = "0123456789abcdef"
	B64   = Alnum + "+/"
	URL   = Alnum + "_-"
)
