package up

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type RunReport struct {
	RunID         string       `json:"run_id"`
	Config        Config       `json:"config"`
	Errors        []string     `json:"errors,omitempty"`
	SchemaVersion string       `json:"schema_version"`
	StartedAt     time.Time    `json:"started_at"`
	FinishedAt    time.Time    `json:"finished_at"`
	ConfigName    string       `json:"config_name"`
	Image         ImageReport  `json:"image"`
	TargetVersion string       `json:"target_version,omitempty"`
	Cases         []CaseReport `json:"cases"`
	Limitations   []string     `json:"limitations"`
}

type ImageReport struct {
	Reference   string   `json:"reference"`
	ID          string   `json:"id,omitempty"`
	RepoDigests []string `json:"repo_digests,omitempty"`
}

type CaseReport struct {
	Image           ImageReport     `json:"image"`
	TargetVersion   string          `json:"target_version,omitempty"`
	ReportError     string          `json:"report_error,omitempty"`
	SchemaVersion   string          `json:"schema_version"`
	Case            CaseSpec        `json:"case"`
	Execution       ExecutionReport `json:"execution"`
	Expected        Expected        `json:"expected"`
	Observed        SnapshotResult  `json:"observed"`
	Protected       SnapshotResult  `json:"protected"`
	ProtectedBefore SnapshotResult  `json:"protected_before"`
	Findings        []Finding       `json:"findings"`
	Outcome         string          `json:"outcome"`
	Completeness    string          `json:"completeness"`
	Cleanup         CleanupReport   `json:"cleanup"`
	Limitations     []string        `json:"limitations"`
}

type ExecutionReport struct {
	Disposition     string `json:"disposition"`
	Interrupted     bool   `json:"interrupted"`
	ExitCode        int    `json:"exit_code"`
	TimedOut        bool   `json:"timed_out"`
	DurationMillis  int64  `json:"duration_millis"`
	Stdout          string `json:"stdout,omitempty"`
	Stderr          string `json:"stderr,omitempty"`
	StdoutTruncated bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated bool   `json:"stderr_truncated,omitempty"`
	Error           string `json:"error,omitempty"`
}

type CleanupReport struct {
	Attempted bool   `json:"attempted"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
}

func SaveJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f, err := os.CreateTemp(filepath.Dir(path), ".unpackproof-report-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	defer f.Close()
	if err := f.Chmod(0644); err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func HumanCase(r CaseReport) string {
	line := fmt.Sprintf("%s %q", r.Outcome, r.Case.ID)
	if len(r.Findings) > 0 || r.ReportError != "" || (r.Cleanup.Attempted && !r.Cleanup.OK) {
		line += "\n"
	}
	for _, f := range r.Findings {
		if f.Path != "" {
			line += fmt.Sprintf("  - %q %q: %q\n", f.ID, f.Path, f.Message)
		} else {
			line += fmt.Sprintf("  - %q: %q\n", f.ID, f.Message)
		}
	}
	if r.ReportError != "" {
		line += fmt.Sprintf("  - report-error: %q\n", r.ReportError)
	}
	if r.Cleanup.Attempted && !r.Cleanup.OK {
		line += fmt.Sprintf("  - cleanup-error: %q\n", r.Cleanup.Error)
	}
	return line
}

func Limitations() []string {
	return []string{
		"Filesystem oracle is snapshot-based; transient mutations undone before snapshot can remain unobserved.",
		"v0.1 covers Linux filesystem semantics inside Docker containers.",
		"Corpus uses synthetic benign TAR fixtures only and is not a security scanner.",
		"Captured stdout and stderr are bounded and may be truncated.",
	}
}
