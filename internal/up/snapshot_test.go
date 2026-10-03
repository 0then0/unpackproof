package up

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func observedTree(objects ...ObservedObject) SnapshotResult {
	return SnapshotResult{Root: &ObservedObject{Path: ".", Type: "dir", Mode: "0755", Dev: 1, Ino: 1}, Complete: true, Objects: objects}
}
func protectedTree() SnapshotResult {
	return observedTree(ObservedObject{Path: "sentinel.txt", Type: "file", Size: 19, SHA256: file("sentinel.txt", "protected sentinel\n").SHA256, Mode: "0644", Dev: 1, Ino: 2})
}
func expectedFile() ObservedObject {
	return ObservedObject{Path: "hello.txt", Type: "file", Size: 18, SHA256: file("hello.txt", "hello unpackproof\n").SHA256, Mode: "0644"}
}
func TestComparePassesExpectedTree(t *testing.T) {
	spec, _ := BuildCase("file", "allow", "replace")
	c := Compare(spec, observedTree(expectedFile()), protectedTree(), protectedTree(), 0, false)
	if len(c.Findings) != 0 || !c.Complete {
		t.Fatalf("unexpected comparison: %#v", c)
	}
}
func TestCompareDetectsContractViolations(t *testing.T) {
	spec, _ := BuildCase("file", "allow", "replace")
	for _, tc := range []struct {
		name, id string
		mutate   func(*SnapshotResult, *SnapshotResult)
	}{
		{"no-op", "missing-object", func(o, p *SnapshotResult) { o.Objects = nil }},
		{"wrong bytes", "wrong-content", func(o, p *SnapshotResult) { o.Objects[0].SHA256 = file("x", "wrong").SHA256 }},
		{"wrong permissions", "wrong-permissions", func(o, p *SnapshotResult) { o.Objects[0].Mode = "0000" }},
		{"protected bytes", "protected-changed", func(o, p *SnapshotResult) { p.Objects[0].SHA256 = file("x", "changed").SHA256 }},
		{"protected mode", "protected-changed", func(o, p *SnapshotResult) { p.Objects[0].Mode = "0000" }},
		{"protected identity", "protected-changed", func(o, p *SnapshotResult) { p.Objects[0].Ino++ }},
		{"protected root", "protected-changed", func(o, p *SnapshotResult) { p.Root.Mode = "0000" }},
		{"destination symlink", "wrong-root-type", func(o, p *SnapshotResult) { o.Root.Type = "symlink" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, p := observedTree(expectedFile()), protectedTree()
			tc.mutate(&o, &p)
			assertFinding(t, Compare(spec, o, protectedTree(), p, 0, false), tc.id)
		})
	}
}
func TestCompareDetectsHardlinkIdentity(t *testing.T) {
	spec, _ := BuildCase("hardlink", "allow", "replace")
	hash := file("original.txt", "same inode\n").SHA256
	for _, same := range []bool{true, false} {
		obs := observedTree(ObservedObject{Path: "hard.txt", Type: "file", Size: 11, SHA256: hash, Mode: "0644", Dev: 1, Ino: 10}, ObservedObject{Path: "original.txt", Type: "file", Size: 11, SHA256: hash, Mode: "0644", Dev: 1, Ino: 10})
		if !same {
			obs.Objects[0].Ino++
		}
		c := Compare(spec, obs, protectedTree(), protectedTree(), 0, false)
		if same && len(c.Findings) != 0 {
			t.Fatalf("same inode rejected: %#v", c)
		}
		if !same {
			assertFinding(t, c, "wrong-link-identity")
		}
	}
}
func TestCompareTimeoutAndRejectAll(t *testing.T) {
	spec, _ := BuildCase("file", "allow", "replace")
	assertFinding(t, Compare(spec, observedTree(), protectedTree(), protectedTree(), -1, true), "execution-timeout")
	assertFinding(t, Compare(spec, observedTree(), protectedTree(), protectedTree(), 1, false), "unexpected-exit-code")
}
func TestSnapshotDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	if err := os.WriteFile(filepath.Join(external, "hidden"), []byte("outside"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	s, err := Snapshot(root, SnapshotLimit{})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Objects) != 1 || s.Objects[0].Type != "symlink" || s.Objects[0].LinkTarget != external {
		t.Fatalf("symlink followed: %#v", s)
	}
	link := filepath.Join(t.TempDir(), "root")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	s, err = Snapshot(link, SnapshotLimit{})
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := BuildCase("links-denied", "reject", "replace")
	assertFinding(t, Compare(spec, s, protectedTree(), protectedTree(), 1, false), "wrong-root-type")
}
func TestSnapshotLimitsAndRealHardlink(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a")
	b := filepath.Join(root, "b")
	if err := os.WriteFile(a, []byte("contents"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, b); err != nil {
		t.Fatal(err)
	}
	s, err := Snapshot(root, SnapshotLimit{})
	if err != nil {
		t.Fatal(err)
	}
	if s.Objects[0].Ino != s.Objects[1].Ino || s.Objects[0].Dev != s.Objects[1].Dev {
		t.Fatal("real hardlink identity lost")
	}
	for _, limit := range []SnapshotLimit{{MaxEntries: 1}, {MaxFileBytes: 1}} {
		s, err = Snapshot(root, limit)
		if err != nil {
			t.Fatal(err)
		}
		if s.Complete || s.Incomplete == "" {
			t.Fatalf("limit not enforced: %#v", s)
		}
	}
}
func TestFindingsAreDeterministic(t *testing.T) {
	spec, _ := BuildCase("nested", "allow", "replace")
	var last string
	for i := 0; i < 20; i++ {
		c := Compare(spec, observedTree(), protectedTree(), protectedTree(), 0, false)
		b, _ := json.Marshal(c.Findings)
		if i > 0 && last != string(b) {
			t.Fatal("finding order changed")
		}
		last = string(b)
	}
}
func assertFinding(t *testing.T, c Comparison, id string) {
	t.Helper()
	for _, f := range c.Findings {
		if f.ID == id {
			return
		}
	}
	t.Fatalf("finding %s not found in %#v", id, c.Findings)
}

func TestSnapshotPreservesSpecialPermissionBits(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "file")
	if err := os.WriteFile(p, []byte("bytes"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode os.FileMode
		want string
	}{{0644 | os.ModeSetuid, "4644"}, {0644 | os.ModeSetgid, "2644"}, {0644 | os.ModeSticky, "1644"}} {
		if err := os.Chmod(p, tc.mode); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != tc.mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) {
			t.Skip("host filesystem strips special permission bits; Linux Docker integration verifies them")
		}
		s, err := Snapshot(root, SnapshotLimit{})
		if err != nil {
			t.Fatal(err)
		}
		if s.Objects[0].Mode != tc.want {
			t.Fatalf("permission bits lost: want %s got %s", tc.want, s.Objects[0].Mode)
		}
	}
}

func TestPermissionStringIncludesSpecialBits(t *testing.T) {
	if got := permissionString(0644 | os.ModeSetuid | os.ModeSetgid | os.ModeSticky); got != "7644" {
		t.Fatalf("special permissions omitted: %s", got)
	}
}
