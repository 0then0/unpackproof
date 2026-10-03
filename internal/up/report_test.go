package up

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHumanReportEscapesUntrustedStrings(t *testing.T) {
	r := CaseReport{Case: CaseSpec{ID: "file"}, Outcome: OutcomeFAIL, RecoveryReport: "/tmp/recovery\nPASS forged\x1b", Cleanup: CleanupReport{Error: "deferred\r\x1b"}, Findings: []Finding{{ID: "unexpected-object", Path: "extra\nPASS forged\x1b[31m", Message: "message\r\x1b"}}}
	text := HumanCase(r)
	if strings.ContainsAny(text, "\r\x1b") || strings.Contains(text, "\nPASS forged") || !strings.Contains(text, `\nPASS forged\x1b`) {
		t.Fatalf("unsafe human output: %q", text)
	}
}
func TestSaveJSONIsAtomicAndReportsFailure(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "case.json")
	if err := SaveJSON(p, map[string]string{"outcome": "PASS"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]string
	if err := json.Unmarshal(b, &report); err != nil || report["outcome"] != "PASS" {
		t.Fatalf("invalid report: %s %v", b, err)
	}
	blocked := filepath.Join(dir, "blocked.json")
	if err := os.Mkdir(blocked, 0755); err != nil {
		t.Fatal(err)
	}
	if err := SaveJSON(blocked, report); err == nil {
		t.Fatal("failed report write was ignored")
	}
	files, _ := filepath.Glob(filepath.Join(dir, ".unpackproof-report-*"))
	if len(files) != 0 {
		t.Fatalf("temporary reports leaked: %v", files)
	}
}
