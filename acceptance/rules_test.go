package acceptance

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArtifactAcceptanceUsesActualBoundedFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "report.json"), []byte(`{"result":"recorded"}`), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := CheckArtifact(t.Context(), root, Spec{Type: "artifact", Path: "report.json", Format: "json"})
	if err != nil || len(result.SHA256) != 64 || result.Bytes == 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if _, err := CheckArtifact(t.Context(), root, Spec{Type: "artifact", Path: "report.json", Format: "json", SHA256: strings.Repeat("0", 64)}); err == nil {
		t.Fatal("accepted wrong hash")
	}
	if err := os.WriteFile(filepath.Join(root, "bad.json"), []byte(`not json`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckArtifact(t.Context(), root, Spec{Type: "artifact", Path: "bad.json", Format: "json"}); err == nil {
		t.Fatal("accepted invalid JSON")
	}
	if err := os.WriteFile(filepath.Join(root, "report.md"), []byte("# Evidence\n\n## Result\nVerified file"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckArtifact(t.Context(), root, Spec{Type: "artifact", Path: "report.md", Format: "markdown", RequiredHeadings: []string{"Result"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckArtifact(t.Context(), root, Spec{Type: "artifact", Path: "report.md", Format: "markdown", RequiredHeadings: []string{"Missing"}}); err == nil {
		t.Fatal("accepted missing heading")
	}
}

func TestArtifactAcceptanceRejectsTraversalAndSymlinks(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	secret := filepath.Join(outside, "outside.txt")
	if err := os.WriteFile(secret, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "link.txt")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"../outside.txt", secret, "link.txt", "."} {
		if _, err := CheckArtifact(t.Context(), root, Spec{Type: "artifact", Path: path, Format: "text"}); err == nil {
			t.Fatalf("accepted %q", path)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "large.txt"), []byte(strings.Repeat("x", (2<<20)+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckArtifact(t.Context(), root, Spec{Type: "artifact", Path: "large.txt", Format: "text"}); err == nil {
		t.Fatal("accepted oversized artifact")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := CheckArtifact(ctx, root, Spec{Type: "artifact", Path: "large.txt", Format: "text"}); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestGoalAcceptanceRejectsAmbiguousRules(t *testing.T) {
	for _, spec := range []Spec{{Type: "llm"}, {Type: "confirmed_findings", MinCount: 0}, {Type: "confirmed_findings", MinCount: 1001}, {Type: "manual", MinCount: 1}, {Type: "artifact", Path: "file", Format: "bash"}} {
		if err := spec.Validate(); err == nil {
			t.Fatalf("accepted %+v", spec)
		}
	}
}
