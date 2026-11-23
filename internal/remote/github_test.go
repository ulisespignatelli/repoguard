package remote

import (
	"testing"
)

func TestParseRepo(t *testing.T) {
	ok := map[string]string{
		"https://github.com/ulisespignatelli/argos":     "ulisespignatelli/argos",
		"https://github.com/ulisespignatelli/argos.git": "ulisespignatelli/argos",
		"github.com/ulisespignatelli/argos/":            "ulisespignatelli/argos",
		"ulisespignatelli/secret-guard.v2":              "ulisespignatelli/secret-guard.v2",
		"http://www.github.com/Org-Name/repo_name":      "Org-Name/repo_name",
	}
	for in, want := range ok {
		r, good := ParseRepo(in)
		if !good || r.FullName() != want {
			t.Errorf("%s -> %v %s", in, good, r.FullName())
		}
	}
	for _, bad := range []string{"https://gitlab.com/a/b", "a/b/c", "../etc/passwd", "-x/y", "https://github.com/a", "a; rm -rf /"} {
		if _, good := ParseRepo(bad); good {
			t.Errorf("%q no debería aceptarse", bad)
		}
	}
	if IsGitHubURL("ulisespignatelli/argos") || !IsGitHubURL("https://github.com/a/b") {
		t.Error("IsGitHubURL debería exigir github.com")
	}
}

func TestBlobURL(t *testing.T) {
	r := Repo{Owner: "o", Name: "r"}
	if got := r.BlobURL("HEAD", "src/mi archivo.js", 7); got != "https://github.com/o/r/blob/HEAD/src/mi%20archivo.js#L7" {
		t.Fatal(got)
	}
}
