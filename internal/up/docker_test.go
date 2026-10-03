package up

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestFinishWithCleanupPreservesEvidenceOnPersistenceFailure(t *testing.T) {
	for _, recoveryAvailable := range []bool{true, false} {
		name := "recovery-succeeds"
		if !recoveryAvailable {
			name = "all-storage-unavailable"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "reports")
			initial := RunReport{RunID: "review", Image: ImageReport{ID: "sha256:test"}, Config: Config{Command: []string{"extract"}}}
			if err := SaveJSON(filepath.Join(out, "run.json"), initial); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(out, out+".initial"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(out, []byte("filesystem unavailable"), 0600); err != nil {
				t.Fatal(err)
			}
			recoveryDir := filepath.Join(dir, "recovery")
			if recoveryAvailable {
				if err := os.Mkdir(recoveryDir, 0700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(recoveryDir, nil, 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("TMPDIR", recoveryDir)
			log := filepath.Join(dir, "commands")
			witness := filepath.Join(dir, "before-cleanup.json")
			t.Setenv("REVIEW_COMMAND_LOG", log)
			t.Setenv("REVIEW_WITNESS", witness)
			// Capture the recovery checkpoint at the first destructive operation.
			script := `#!/bin/sh
echo "$*" >> "$REVIEW_COMMAND_LOG"
case "$1" in
 ps) echo owned-target ;;
 rm) cp "$TMPDIR"/unpackproof-recovery-*/run.json "$REVIEW_WITNESS" || exit 1 ;;
 volume) if [ "$2" = ls ]; then echo owned-volume; fi ;;
esac
`
			if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			spec, err := BuildCase("file", "allow", "replace")
			if err != nil {
				t.Fatal(err)
			}
			cr := CaseReport{Case: spec, Outcome: OutcomeFAIL, Completeness: "complete", Observed: SnapshotResult{Complete: true, Root: &ObservedObject{Path: ".", Type: "dir"}, Objects: []ObservedObject{{Path: "hello.txt", Type: "file", SHA256: "observed-hash"}}}, Findings: []Finding{{ID: "wrong-content", Path: "hello.txt"}}}
			runner := dockerRunner{runID: "review", report: &initial}
			result := runner.finishWithCleanup("file", out, cr)
			if result.Outcome != OutcomeFAIL || result.ReportError == "" {
				t.Fatalf("lost verdict or persistence error: %#v", result)
			}
			commands, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			if recoveryAvailable {
				if result.RecoveryReport == "" || !result.Cleanup.OK || !result.Cleanup.Attempted {
					t.Fatalf("recovery/cleanup failed: %#v", result)
				}
				for _, path := range []string{witness, result.RecoveryReport} {
					data, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					var saved RunReport
					if err := json.Unmarshal(data, &saved); err != nil {
						t.Fatal(err)
					}
					if saved.Image.ID != "sha256:test" || len(saved.Config.Command) != 1 || len(saved.Cases) != 1 || saved.Cases[0].Outcome != OutcomeFAIL || saved.Cases[0].Observed.Objects[0].SHA256 != "observed-hash" || saved.Cases[0].Findings[0].ID != "wrong-content" {
						t.Fatalf("incomplete recovery evidence: %#v", saved)
					}
					if saved.Cases[0].Cleanup.Attempted != (path == result.RecoveryReport) {
						t.Fatal("cleanup preceded persistence or its final status was lost")
					}
				}
			} else {
				if result.RecoveryReport != "" || result.Cleanup.Attempted || result.Cleanup.OK || result.Cleanup.Error == "" {
					t.Fatalf("unsafe cleanup after total persistence failure: %#v", result)
				}
				if strings.Contains(string(commands), "rm ") || !strings.Contains(string(commands), "kill owned-target") || !strings.Contains(string(commands), "label=org.unpackproof.run=review") || !strings.Contains(string(commands), "name=^/unpackproof-review-file-target$") {
					t.Fatalf("target not stopped independently of destructive cleanup: %s", commands)
				}
			}
		})
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

func TestDecodeSnapshotRejectsContradictoryAbsence(t *testing.T) {
	base := SnapshotResult{RootMissing: true, Complete: true, Objects: []ObservedObject{}, FixtureRoot: &ObservedObject{Path: ".", Type: "dir", Dev: 1, Ino: 1}}
	for _, mutate := range []func(*SnapshotResult){
		func(s *SnapshotResult) { s.Root = &ObservedObject{Path: ".", Type: "dir"} },
		func(s *SnapshotResult) { s.Objects = []ObservedObject{{Path: "x", Type: "dir"}} },
		func(s *SnapshotResult) { s.Complete = false; s.Incomplete = "limit exceeded" },
		func(s *SnapshotResult) { s.Incomplete = "error" },
		func(s *SnapshotResult) { s.FixtureRoot = nil },
		func(s *SnapshotResult) { s.FixtureRoot = &ObservedObject{Path: ".", Type: "dir"} },
	} {
		s := base
		mutate(&s)
		data, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		if err := decodeSnapshot(data, new(SnapshotResult)); err == nil {
			t.Fatalf("contradictory absence accepted: %s", data)
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
