package up

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == "" {
		d.Duration = 0
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Duration.String())
}

type Config struct {
	SchemaVersion        string   `json:"schema_version"`
	Name                 string   `json:"name"`
	Image                string   `json:"image"`
	Command              []string `json:"command"`
	TargetVersionCommand []string `json:"target_version_command,omitempty"`
	Cases                []string `json:"cases"`
	LinkPolicy           string   `json:"link_policy"`
	OverwritePolicy      string   `json:"overwrite_policy"`
	Limits               Limits   `json:"limits"`
}

type Limits struct {
	Timeout           Duration `json:"timeout"`
	Memory            string   `json:"memory"`
	CPUs              string   `json:"cpus"`
	PIDs              int      `json:"pids"`
	StorageTmpfs      string   `json:"storage_tmpfs"`
	MaxCapturedOutput int      `json:"max_captured_output"`
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return Config{}, errors.New("config must contain exactly one JSON object")
	}
	return normalizeConfig(cfg)
}

func normalizeConfig(cfg Config) (Config, error) {
	if cfg.SchemaVersion == "" {
		cfg.SchemaVersion = "unpackproof.config.v1"
	}
	if cfg.SchemaVersion != "unpackproof.config.v1" {
		return Config{}, fmt.Errorf("unsupported config schema %q", cfg.SchemaVersion)
	}
	if cfg.Image == "" {
		return Config{}, errors.New("image is required")
	}
	if len(cfg.Command) == 0 || strings.TrimSpace(cfg.Command[0]) == "" {
		return Config{}, errors.New("command is required")
	}
	if len(cfg.TargetVersionCommand) > 0 && strings.TrimSpace(cfg.TargetVersionCommand[0]) == "" {
		return Config{}, errors.New("target_version_command executable is empty")
	}
	if cfg.LinkPolicy == "" {
		cfg.LinkPolicy = "allow"
	}
	if cfg.OverwritePolicy == "" {
		cfg.OverwritePolicy = "replace"
	}
	if !oneOf(cfg.LinkPolicy, "allow", "skip", "reject") {
		return Config{}, fmt.Errorf("invalid link_policy %q", cfg.LinkPolicy)
	}
	if !oneOf(cfg.OverwritePolicy, "replace", "preserve", "reject") {
		return Config{}, fmt.Errorf("invalid overwrite_policy %q", cfg.OverwritePolicy)
	}
	if len(cfg.Cases) == 0 {
		for _, c := range AllCases() {
			if c.ID == "links-denied" && cfg.LinkPolicy == "allow" {
				continue
			}
			cfg.Cases = append(cfg.Cases, c.ID)
		}
	}
	seen := make(map[string]bool)
	for _, id := range cfg.Cases {
		if seen[id] {
			return Config{}, fmt.Errorf("duplicate case %q", id)
		}
		seen[id] = true
		if _, err := BuildCase(id, cfg.LinkPolicy, cfg.OverwritePolicy); err != nil {
			return Config{}, err
		}
	}
	// A rejection-only suite cannot establish that the command extracts anything.
	if !seen["file"] {
		cfg.Cases = append([]string{"file"}, cfg.Cases...)
	}
	if cfg.Limits.Timeout.Duration < 0 {
		return Config{}, errors.New("timeout must be positive")
	}
	if cfg.Limits.Timeout.Duration == 0 {
		cfg.Limits.Timeout.Duration = 10 * time.Second
	}
	if cfg.Limits.Memory == "" {
		cfg.Limits.Memory = "256m"
	}
	if cfg.Limits.CPUs == "" {
		cfg.Limits.CPUs = "1"
	}
	if cfg.Limits.PIDs == 0 {
		cfg.Limits.PIDs = 64
	}
	if cfg.Limits.StorageTmpfs == "" {
		cfg.Limits.StorageTmpfs = "16m"
	}
	if cfg.Limits.MaxCapturedOutput == 0 {
		cfg.Limits.MaxCapturedOutput = 65536
	}
	for name, size := range map[string]string{"memory": cfg.Limits.Memory, "storage_tmpfs": cfg.Limits.StorageTmpfs} {
		if !positiveSize.MatchString(size) {
			return Config{}, fmt.Errorf("%s must be a positive size in bytes or b/k/kb/m/mb/g/gb", name)
		}
	}
	cpu, err := strconv.ParseFloat(cfg.Limits.CPUs, 64)
	if err != nil || math.IsNaN(cpu) || math.IsInf(cpu, 0) || cpu <= 0 {
		return Config{}, errors.New("cpus must be a finite positive number")
	}
	if cfg.Limits.PIDs < 1 || cfg.Limits.MaxCapturedOutput < 1 {
		return Config{}, errors.New("pids and max_captured_output must be positive")
	}
	return cfg, nil
}

var positiveSize = regexp.MustCompile(`^[1-9][0-9]*([bBkKmMgG]|[kKmMgG][bB])?$`)

func oneOf(v string, allowed ...string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

func HostDockerArch() string {
	switch runtime.GOARCH {
	case "arm64":
		return "arm64"
	case "amd64":
		return "amd64"
	default:
		return runtime.GOARCH
	}
}

func ConfigSchemaSummary() string {
	return `{
  "schema_version": "unpackproof.config.v1",
  "image": "prepared container image",
  "command": ["argv0", "--archive", "{archive}", "--destination", "{destination}"],
  "target_version_command": ["argv0", "--version"],
  "cases": ["file", "nested", "empty", "unicode", "pax", "duplicate", "existing", "symlink", "hardlink", "links-denied", "truncated"],
  "link_policy": "allow | skip | reject",
  "overwrite_policy": "replace | preserve | reject",
  "limits": {"timeout": "10s", "memory": "256m", "cpus": "1", "pids": 64, "storage_tmpfs": "16m", "max_captured_output": 65536}
}`
}
