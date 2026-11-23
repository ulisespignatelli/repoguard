// Package remote trae repositorios de GitHub para revisarlos: los clona (solo la ultima version) en una
// carpeta temporal, sin ejecutar nada, y la borra al terminar.
//
// El token (GITHUB_TOKEN o GH_TOKEN) es opcional: hace falta para repos privados y sube el limite de la API.
// Nunca se pasa por la linea de comandos ni se escribe en disco: viaja como cabecera HTTP de git.
package remote

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// Repo identifica un repositorio de GitHub.
type Repo struct {
	Owner, Name string
	Private     bool
	Fork        bool
	Archived    bool
}

// FullName devuelve "duenio/repo".
func (r Repo) FullName() string { return r.Owner + "/" + r.Name }

// CloneURL es la URL HTTPS del repositorio.
func (r Repo) CloneURL() string { return "https://github.com/" + r.FullName() + ".git" }

// BlobURL arma el enlace a una linea en GitHub (ref puede ser HEAD o un commit).
func (r Repo) BlobURL(ref, path string, line int) string {
	return fmt.Sprintf("https://github.com/%s/blob/%s/%s#L%d", r.FullName(), ref, escapePath(path), line)
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

var namePart = `[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})`
var targetRe = regexp.MustCompile(`^(?:https?://)?(?:www\.)?github\.com/(` + namePart + `)/(` + namePart + `)/?$`)
var shortRe = regexp.MustCompile(`^(` + namePart + `)/(` + namePart + `)$`)

// ParseRepo acepta "https://github.com/duenio/repo", "github.com/duenio/repo" o "duenio/repo".
func ParseRepo(s string) (Repo, bool) {
	s = strings.TrimSpace(s)
	if m := targetRe.FindStringSubmatch(s); m != nil {
		return Repo{Owner: m[1], Name: strings.TrimSuffix(m[2], ".git")}, true
	}
	if m := shortRe.FindStringSubmatch(s); m != nil {
		return Repo{Owner: m[1], Name: m[2]}, true
	}
	return Repo{}, false
}

// IsGitHubURL indica si el argumento es claramente una URL de GitHub (y no una ruta local).
func IsGitHubURL(s string) bool {
	return targetRe.MatchString(strings.TrimSpace(s)) && strings.Contains(s, "github.com")
}

// Token lee el token de las variables de entorno habituales.
func Token() string {
	if t := os.Getenv("GITHUB_TOKEN"); t != "" {
		return t
	}
	return os.Getenv("GH_TOKEN")
}

// Clone clona la ultima version del repositorio en una carpeta temporal. cleanup la borra.
func Clone(ctx context.Context, r Repo, token string) (dir string, cleanup func(), err error) {
	dir, err = os.MkdirTemp("", "repoguard-*")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	noHooks, err := os.MkdirTemp("", "repoguard-nohooks-*")
	if err != nil {
		cleanup()
		return "", nil, err
	}
	defer os.RemoveAll(noHooks)

	args := []string{
		"-c", "core.hooksPath=" + noHooks, // nunca ejecutar hooks
		"-c", "protocol.file.allow=never", // sin submodulos ni rutas locales
		"-c", "core.symlinks=true", // los enlaces se crean como enlaces (no se siguen) para poder informarlos
	}
	if token != "" {
		basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
		args = append(args, "-c", "http.https://github.com/.extraheader=AUTHORIZATION: basic "+basic)
	}
	args = append(args, "clone", "--quiet", "--depth", "1", "--no-recurse-submodules", "--no-tags", r.CloneURL(), dir)
	cmd := exec.CommandContext(ctx, "git", args...) // #nosec G204: sin shell; URL validada por ParseRepo
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_LFS_SKIP_SMUDGE=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		msg := strings.TrimSpace(string(out))
		if token != "" {
			msg = strings.ReplaceAll(msg, token, "****")
		}
		if strings.Contains(msg, "not found") || strings.Contains(msg, "Authentication failed") ||
			strings.Contains(msg, "could not read Username") {
			return "", nil, fmt.Errorf("no se pudo acceder a %s: no existe o es privado (para repos privados definí GITHUB_TOKEN) [%s]", r.FullName(), msg)
		}
		return "", nil, fmt.Errorf("git clone %s falló: %s", r.FullName(), msg)
	}
	return dir, cleanup, nil
}
