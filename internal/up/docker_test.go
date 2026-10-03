package up

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestReplacePlaceholdersDoesNotUseShell(t *testing.T) {
	got := replacePlaceholders([]string{"tool", "--archive={archive}", "$(touch /tmp/bad)", "`bad`", "{destination}"})
	if got[1] != "--archive=/fixture/input/archive.tar" {
		t.Fatalf("archive placeholder not replaced: %#v", got)
	}
	if got[2] != "$(touch /tmp/bad)" || got[3] != "`bad`" {
		t.Fatalf("argv strings should remain literal: %#v", got)
	}
	if got[4] != "/fixture/destination" {
		t.Fatalf("destination placeholder not replaced: %#v", got)
	}
}

func TestLimitBufferTruncates(t *testing.T) {
	b := limitBuffer{limit: 4}
	if n, err := b.Write([]byte("123456")); n != 6 || err != nil {
		t.Fatalf("write: %d %v", n, err)
	}
	b.Write([]byte("more"))
	if b.String() != "1234" || !b.truncated {
		t.Fatalf("unbounded output: %#v", b)
	}
}
func TestDecodeSnapshotRejectsMalformedEvidence(t *testing.T) {
	for _, data := range []string{`{}`, `{"root":{"path":".","type":"dir"},"complete":true,"objects":[{"path":"../outside","type":"file"}]}`, `{"root":{"path":".","type":"dir"},"complete":true,"objects":[{"path":"x","type":"file","sha256":"wrong"}]}`, `{"root":{"path":".","type":"dir"},"complete":true,"objects":[]} {}`} {
		var s SnapshotResult
		if err := decodeSnapshot([]byte(data), &s); err == nil {
			t.Fatalf("malformed snapshot accepted: %s", data)
		}
	}
}
func TestRunIDsAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id, err := newRunID()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != 32 || seen[id] {
			t.Fatalf("non-unique id %q", id)
		}
		seen[id] = true
	}
}

func TestPythonAdapterShebangIsExecutable(t *testing.T) {
	p := filepath.Join("..", "..", "examples", "python-tarfile", "adapter.py")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte("#!")) || st.Mode().Perm()&0100 == 0 {
		t.Fatal("Ruff EXE001: Python adapter shebang requires executable permissions")
	}
}
