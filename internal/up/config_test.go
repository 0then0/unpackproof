package up

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(`{"image":"x","command":["x"],"surprise":true}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("expected unknown field to be rejected")
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(`{"image":"x","command":["x"]}`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LinkPolicy != "allow" || cfg.OverwritePolicy != "replace" || len(cfg.Cases) == 0 {
		t.Fatalf("defaults not applied: %#v", cfg)
	}
}

func TestConfigRequiresPositiveControl(t *testing.T) {
	cfg, err := normalizeConfig(Config{Image: "x", Command: []string{"x"}, Cases: []string{"truncated", "links-denied"}, LinkPolicy: "reject"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cases[0] != "file" {
		t.Fatalf("missing positive control: %v", cfg.Cases)
	}
	cfg, err = normalizeConfig(Config{Image: "x", Command: []string{"x"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range cfg.Cases {
		if id == "links-denied" {
			t.Fatal("allow suite contains forbidden-links case")
		}
	}
}
func TestConfigRejectsUnboundedOrInvalidLimits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		limits Limits
	}{
		{"zero memory", Limits{Memory: "0"}},
		{"invalid memory", Limits{Memory: "unlimited"}},
		{"zero storage", Limits{StorageTmpfs: "0m"}},
		{"negative pids", Limits{PIDs: -1}},
		{"zero cpus", Limits{CPUs: "0"}},
		{"nan cpus", Limits{CPUs: "NaN"}},
		{"infinite cpus", Limits{CPUs: "+Inf"}},
		{"negative output", Limits{MaxCapturedOutput: -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := normalizeConfig(Config{Image: "x", Command: []string{"x"}, Limits: tc.limits}); err == nil {
				t.Fatal("unsafe limit accepted")
			}
		})
	}
}
func TestConfigRejectsTrailingJSONAndDuplicateCases(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(`{"image":"x","command":["x"]} {}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("trailing JSON accepted")
	}
	if _, err := normalizeConfig(Config{Image: "x", Command: []string{"x"}, Cases: []string{"file", "file"}}); err == nil {
		t.Fatal("duplicate case accepted")
	}
}
