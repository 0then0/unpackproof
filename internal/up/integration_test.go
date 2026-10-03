//go:build integration

package up

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func integrationGuest(t *testing.T) string {
	t.Helper()
	p := os.Getenv("UNPACKPROOF_GUEST")
	if p == "" {
		t.Fatal("set UNPACKPROOF_GUEST to the Linux guest binary")
	}
	p, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func integrationConfig() Config {
	return Config{Image: "unpackproof/python-tarfile:0.1", Command: []string{"/adapters/python-tarfile.py", "--archive", "{archive}", "--destination", "{destination}"}, Cases: []string{"file"}}
}
func integrationOut(t *testing.T, suffix string) string {
	t.Helper()
	root := os.Getenv("UNPACKPROOF_REPORT_ROOT")
	if root == "" {
		root = t.TempDir()
	}
	p := filepath.Join(root, strings.ReplaceAll(t.Name(), "/", "_"), suffix)
	if err := os.MkdirAll(p, 0755); err != nil {
		t.Fatal(err)
	}
	return p
}
func readRun(t *testing.T, out string) RunReport {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(out, "run.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r RunReport
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}
func assertNoOwnedResources(t *testing.T, id string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, args := range [][]string{{"ps", "-aq", "--filter", "label=org.unpackproof.run=" + id}, {"volume", "ls", "-q", "--filter", "label=org.unpackproof.run=" + id}} {
		var b bytes.Buffer
		if err := docker(ctx, &b, nil, args...); err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(b.String()) != "" {
			t.Fatalf("owned resources remain: %s", b.String())
		}
	}
}
func runIntegration(t *testing.T, cfg Config) (RunReport, error) {
	t.Helper()
	out := integrationOut(t, "run")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	err := Run(ctx, cfg, integrationGuest(t), out, &bytes.Buffer{})
	r := readRun(t, out)
	assertNoOwnedResources(t, r.RunID)
	return r, err
}
func requireCase(t *testing.T, r RunReport, id, outcome, finding string) CaseReport {
	t.Helper()
	for _, c := range r.Cases {
		if c.Case.ID == id {
			if c.Outcome != outcome || !c.Cleanup.OK || c.ReportError != "" {
				t.Fatalf("unexpected %s: %#v", id, c)
			}
			if finding != "" {
				assertFinding(t, Comparison{Findings: c.Findings}, finding)
			}
			return c
		}
	}
	t.Fatalf("missing case %s", id)
	return CaseReport{}
}
func TestIntegrationRealAPIs(t *testing.T) {
	for _, name := range []string{"python-tarfile", "node-tar"} {
		t.Run(name, func(t *testing.T) {
			cfg, err := LoadConfig(filepath.Join("..", "..", "configs", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			r, err := runIntegration(t, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if r.Image.ID == "" || r.TargetVersion == "" {
				t.Fatalf("missing provenance: %#v", r)
			}
			for _, c := range r.Cases {
				requireCase(t, r, c.Case.ID, OutcomePASS, "")
			}
		})
	}
}

func TestIntegrationCompatibilityCLIs(t *testing.T) {
	for _, name := range []string{"gnu-tar", "python-cli"} {
		t.Run(name, func(t *testing.T) {
			cfg, err := LoadConfig(filepath.Join("..", "..", "configs", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.LinkPolicy != "allow" || cfg.OverwritePolicy != "replace" || len(cfg.Cases) != len(AllCases())-1 {
				t.Fatalf("compatibility suite must use the default allow/replace corpus: %#v", cfg)
			}
			r, err := runIntegration(t, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if r.Image.ID == "" || r.TargetVersion == "" {
				t.Fatalf("missing provenance: %#v", r)
			}
			for _, c := range r.Cases {
				requireCase(t, r, c.Case.ID, OutcomePASS, "")
				if c.Execution.Disposition != "completed" || (c.Case.ID == "truncated" && c.Execution.ExitCode == 0) {
					t.Fatalf("extraction must complete and detect truncation: %#v", c.Execution)
				}
			}
		})
	}
}

func TestIntegrationMissingRoots(t *testing.T) {
	for _, subpath := range []string{"destination", "protected"} {
		t.Run(subpath, func(t *testing.T) {
			realDocker, err := exec.LookPath("docker")
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			out := integrationOut(t, "run")
			witness := filepath.Join(dir, "before-cleanup.json")
			// Capture the actual absence evidence before destructive cleanup.
			dockerPath, _ := json.Marshal(realDocker)
			reportPath, _ := json.Marshal(filepath.Join(out, "run.json"))
			witnessPath, _ := json.Marshal(witness)
			field := "observed"
			if subpath == "protected" {
				field = "protected"
			}
			wrapper := fmt.Sprintf(`#!/usr/bin/env python3
import json,subprocess,sys
if sys.argv[1]=='rm':
 with open(%s) as f: report=json.load(f)
 case=report['cases'][-1]
 snapshot=case[%q]
 assert case['outcome']=='FAIL' and not case['cleanup']['attempted']
 assert snapshot['root_missing'] and snapshot['root'] is None and snapshot['complete']
 assert snapshot['fixture_root']==case['protected_before']['fixture_root']
 with open(%s,'w') as f: json.dump(report,f)
sys.exit(subprocess.call([%s]+sys.argv[1:]))
`, reportPath, field, witnessPath, dockerPath)
			if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(wrapper), 0755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			cfg := integrationConfig()
			script := "import os;os.rmdir('/fixture/destination')"
			if subpath == "protected" {
				script = "import tarfile,shutil;tarfile.open('/fixture/input/archive.tar').extractall('/fixture/destination',filter='data');shutil.rmtree('/fixture/protected')"
			}
			cfg.Command = []string{"python3", "-c", script}
			r, err := runIntegration(t, cfg)
			if err == nil {
				t.Fatal("missing root passed")
			}
			c := requireCase(t, r, "file", OutcomeFAIL, "missing-"+subpath+"-root")
			if c.Execution.Disposition != "completed" || c.Execution.ExitCode != 0 || c.Completeness != "complete" {
				t.Fatalf("incorrect execution or completeness: %#v", c)
			}
			if subpath == "protected" && (len(c.Observed.Objects) != 1 || c.Observed.Objects[0].SHA256 != c.Expected.Objects[0].SHA256) {
				t.Fatal("protected deletion test did not extract the expected bytes")
			}
			data, err := os.ReadFile(witness)
			if err != nil {
				t.Fatal("missing evidence before cleanup", err)
			}
			var before RunReport
			if err := json.Unmarshal(data, &before); err != nil || len(before.Cases) != 1 || before.Cases[0].Cleanup.Attempted {
				t.Fatalf("invalid pre-cleanup checkpoint: %s %v", data, err)
			}
			data, err = os.ReadFile(filepath.Join(out, "file.json"))
			var saved CaseReport
			if err != nil || json.Unmarshal(data, &saved) != nil || saved.Outcome != OutcomeFAIL || !saved.Cleanup.OK || saved.Observed.RootMissing != c.Observed.RootMissing || saved.Protected.RootMissing != c.Protected.RootMissing {
				t.Fatalf("case evidence or cleanup lost: %s %v", data, err)
			}
		})
	}
}

func TestIntegrationObservationFailures(t *testing.T) {
	for _, mode := range []string{"observer-error", "fixture-unmounted", "incomplete"} {
		t.Run(mode, func(t *testing.T) {
			realDocker, err := exec.LookPath("docker")
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			dockerPath, _ := json.Marshal(realDocker)
			wrapper := fmt.Sprintf(`#!/usr/bin/env python3
import json,subprocess,sys
args=sys.argv[1:]
if 'snapshot' in args and args[-1]=='destination':
 mode=%q
 if mode=='observer-error':
  sys.stderr.write('lstat /fixture/destination: no such file or directory\n')
  sys.exit(1)
 if mode=='fixture-unmounted':
  i=next(i for i,a in enumerate(args) if a.endswith(':/fixture'))
  del args[i-1:i+1]
 if mode=='incomplete':
  s=json.loads(subprocess.check_output([%s]+args))
  s['complete']=False
  s['incomplete_reason']='controlled observation limit'
  print(json.dumps(s))
  sys.exit(0)
sys.exit(subprocess.call([%s]+args))
`, mode, dockerPath, dockerPath)
			if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(wrapper), 0755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			cfg := integrationConfig()
			if mode != "incomplete" {
				cfg.Command = []string{"python3", "-c", "import os;os.rmdir('/fixture/destination')"}
			}
			r, err := runIntegration(t, cfg)
			if err == nil {
				t.Fatal("observation failure passed")
			}
			outcome, finding := OutcomeInfrastructureError, "infrastructure-snapshot-destination"
			if mode == "incomplete" {
				outcome, finding = OutcomeUNRESOLVED, "incomplete-observation"
			}
			c := requireCase(t, r, "file", outcome, finding)
			if c.Completeness != "incomplete" {
				t.Fatal("failed observation marked complete")
			}
		})
	}
}

func TestIntegrationMissingRootDuringTimeoutAndInterruption(t *testing.T) {
	for _, interrupted := range []bool{false, true} {
		name := "timeout"
		if interrupted {
			name = "interruption"
		}
		t.Run(name, func(t *testing.T) {
			cfg := integrationConfig()
			cfg.Command = []string{"python3", "-c", "import os,time;os.rmdir('/fixture/destination');print('removed',flush=True);time.sleep(30)"}
			cfg.Limits.Timeout.Duration = 2 * time.Second
			out := integrationOut(t, "run")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if interrupted {
				// Cancel only after a running target has removed the disposable root.
				go func() {
					deadline := time.Now().Add(15 * time.Second)
					for time.Now().Before(deadline) && ctx.Err() == nil {
						var b bytes.Buffer
						if data, err := os.ReadFile(filepath.Join(out, "run.json")); err == nil {
							var r RunReport
							if json.Unmarshal(data, &r) == nil {
								checkCtx, stop := context.WithTimeout(ctx, time.Second)
								err := docker(checkCtx, &b, nil, "inspect", "unpackproof-"+r.RunID+"-file-target", "--format", "{{.State.Running}}")
								if err == nil && strings.TrimSpace(b.String()) == "true" {
									b.Reset()
									err = docker(checkCtx, &b, nil, "exec", "unpackproof-"+r.RunID+"-file-keeper", "/unpackproof-guest", "snapshot", "--root", "/fixture", "--subpath", "destination")
								}
								stop()
								var s SnapshotResult
								if err == nil && decodeSnapshot(b.Bytes(), &s) == nil && s.RootMissing {
									cancel()
									return
								}
							}
						}
						time.Sleep(50 * time.Millisecond)
					}
				}()
				cfg.Limits.Timeout.Duration = 20 * time.Second
			}
			err := Run(ctx, cfg, integrationGuest(t), out, &bytes.Buffer{})
			if err == nil {
				t.Fatal("incomplete execution passed")
			}
			r := readRun(t, out)
			finding := "execution-timeout"
			if interrupted {
				finding = "execution-interrupted"
			}
			c := requireCase(t, r, "file", OutcomeUNRESOLVED, finding)
			if !c.Observed.RootMissing {
				t.Fatal("missing root evidence lost after incomplete execution")
			}
			assertNoOwnedResources(t, r.RunID)
		})
	}
}
func TestIntegrationInvocationAndPositiveControl(t *testing.T) {
	t.Run("missing-executable", func(t *testing.T) {
		cfg := integrationConfig()
		cfg.Command = []string{"/does-not-exist"}
		cfg.Cases = []string{"truncated", "links-denied"}
		cfg.LinkPolicy = "reject"
		r, err := runIntegration(t, cfg)
		if err == nil {
			t.Fatal("missing executable passed")
		}
		for _, id := range []string{"file", "truncated", "links-denied"} {
			requireCase(t, r, id, OutcomeInfrastructureError, "infrastructure-target")
		}
	})
	t.Run("reject-only", func(t *testing.T) {
		cfg := integrationConfig()
		cfg.Command = []string{"/unpackproof-guest", "adapter", "reject-all"}
		cfg.Cases = []string{"truncated", "links-denied"}
		cfg.LinkPolicy = "reject"
		r, err := runIntegration(t, cfg)
		if err == nil {
			t.Fatal("reject-all suite passed")
		}
		requireCase(t, r, "file", OutcomeFAIL, "missing-object")
		requireCase(t, r, "truncated", OutcomePASS, "")
	})
	t.Run("genuine-exit-127", func(t *testing.T) {
		cfg := integrationConfig()
		cfg.Command = []string{"python", "-c", "raise SystemExit(127)"}
		cfg.Cases = []string{"truncated"}
		r, err := runIntegration(t, cfg)
		if err == nil {
			t.Fatal("positive control passed")
		}
		c := requireCase(t, r, "truncated", OutcomePASS, "")
		if c.Execution.Disposition != "completed" || c.Execution.ExitCode != 127 {
			t.Fatalf("genuine exit misclassified: %#v", c.Execution)
		}
	})
}
func TestIntegrationOracleRegressions(t *testing.T) {
	extract := "import os,tarfile;tarfile.open('/fixture/input/archive.tar').extractall('/fixture/destination',filter='data');"
	for _, tc := range []struct{ name, script, finding string }{
		{"permissions", extract + "os.chmod('/fixture/destination/hello.txt',0)", "wrong-permissions"},
		{"protected-permissions", extract + "os.chmod('/fixture/protected/sentinel.txt',0)", "protected-changed"},
		{"setuid-permissions", extract + "os.chmod('/fixture/destination/hello.txt',0o4644)", "wrong-permissions"},
		{"protected-setuid", extract + "os.chmod('/fixture/protected/sentinel.txt',0o4644)", "protected-changed"},
		{"protected-replacement", extract + "import shutil;shutil.rmtree('/fixture/protected');os.mkdir('/fixture/protected');open('/fixture/protected/sentinel.txt','w').write('protected sentinel\\n')", "protected-changed"},
		{"root-symlink", "import os;os.rmdir('/fixture/destination');os.symlink('/fixture/scratch','/fixture/destination');raise SystemExit(1)", "wrong-root-type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := integrationConfig()
			cfg.Command = []string{"python", "-c", tc.script}
			if tc.name == "root-symlink" {
				cfg.Cases = []string{"links-denied"}
				cfg.LinkPolicy = "reject"
			}
			r, err := runIntegration(t, cfg)
			if err == nil {
				t.Fatal("broken adapter passed")
			}
			requireCase(t, r, "file", OutcomeFAIL, tc.finding)
			if tc.name == "root-symlink" {
				requireCase(t, r, "links-denied", OutcomeFAIL, tc.finding)
			}
		})
	}
}
func TestIntegrationPolicies(t *testing.T) {
	for _, policy := range []string{"replace", "preserve", "reject"} {
		t.Run(policy, func(t *testing.T) {
			cfg := integrationConfig()
			cfg.Cases = []string{"duplicate", "existing"}
			cfg.OverwritePolicy = policy
			cfg.Command = append(cfg.Command, "--overwrite-policy", policy)
			r, err := runIntegration(t, cfg)
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"file", "duplicate", "existing"} {
				requireCase(t, r, id, OutcomePASS, "")
			}
		})
	}
	for _, policy := range []string{"skip", "reject"} {
		t.Run("links-"+policy, func(t *testing.T) {
			cfg := integrationConfig()
			cfg.Cases = []string{"links-denied", "symlink", "hardlink"}
			cfg.LinkPolicy = policy
			cfg.Command = append(cfg.Command, "--link-policy", policy)
			r, err := runIntegration(t, cfg)
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"file", "links-denied", "symlink", "hardlink"} {
				requireCase(t, r, id, OutcomePASS, "")
			}
		})
	}
}
func TestIntegrationCapturedOutputAndResourceLimits(t *testing.T) {
	cfg := integrationConfig()
	cfg.Limits = Limits{Memory: "64m", CPUs: "0.5", PIDs: 32, StorageTmpfs: "1m", MaxCapturedOutput: 512}
	cfg.Command = []string{"python", "-c", `import json,os,tarfile
 tarfile.open('/fixture/input/archive.tar').extractall('/fixture/destination',filter='data')
 print(json.dumps({k:open('/sys/fs/cgroup/'+k).read().strip() for k in ['memory.max','pids.max','cpu.max']}))
 try:
  with open('/fixture/scratch/full','wb') as f: f.write(b'x'*(2*1024*1024))
 except OSError as e:
  print('storage_errno='+str(e.errno))
 print('x'*2048)
 `}
	// Keep the inline program independent of indentation in this source file.
	cfg.Command[2] = strings.ReplaceAll(cfg.Command[2], "\n ", "\n")
	r, err := runIntegration(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := requireCase(t, r, "file", OutcomePASS, "")
	if !c.Execution.StdoutTruncated || len(c.Execution.Stdout) != 512 {
		t.Fatal("captured output was not bounded")
	}
	if !strings.Contains(c.Execution.Stdout, `"memory.max": "67108864"`) || !strings.Contains(c.Execution.Stdout, `"pids.max": "32"`) || !strings.Contains(c.Execution.Stdout, `"cpu.max": "50000 100000"`) || !strings.Contains(c.Execution.Stdout, "storage_errno=28") {
		t.Fatalf("limits not active: %s", c.Execution.Stdout)
	}
}
func TestIntegrationTimeoutAndVersionTimeout(t *testing.T) {
	cfg := integrationConfig()
	cfg.Limits.Timeout.Duration = time.Second
	cfg.Command = []string{"python", "-c", "import time;time.sleep(30)"}
	r, err := runIntegration(t, cfg)
	if err == nil {
		t.Fatal("timeout passed")
	}
	requireCase(t, r, "file", OutcomeUNRESOLVED, "execution-timeout")
	cfg = integrationConfig()
	cfg.Limits.Timeout.Duration = time.Second
	cfg.TargetVersionCommand = []string{"python", "-c", "import time;time.sleep(30)"}
	r, err = runIntegration(t, cfg)
	if err == nil || len(r.Errors) == 0 {
		t.Fatal("version timeout was ignored")
	}
	requireCase(t, r, "file", OutcomePASS, "")
}
func TestIntegrationCrossCaseAndConcurrentRuns(t *testing.T) {
	cfg := integrationConfig()
	cfg.Cases = []string{"file", "nested"}
	cfg.Command = []string{"python", "-c", "import os,tarfile;assert os.listdir('/fixture/destination')==[];tarfile.open('/fixture/input/archive.tar').extractall('/fixture/destination',filter='data')"}
	guest := integrationGuest(t)
	var wg sync.WaitGroup
	reports := make([]RunReport, 2)
	failures := make([]error, 2)
	for i := 0; i < 2; i++ {
		out := integrationOut(t, fmt.Sprint(i))
		wg.Add(1)
		go func(i int, out string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			failures[i] = Run(ctx, cfg, guest, out, &bytes.Buffer{})
			b, err := os.ReadFile(filepath.Join(out, "run.json"))
			if err == nil {
				err = json.Unmarshal(b, &reports[i])
			}
			failures[i] = errors.Join(failures[i], err)
		}(i, out)
	}
	wg.Wait()
	for i, r := range reports {
		if failures[i] != nil {
			t.Fatal(failures[i])
		}
		requireCase(t, r, "file", OutcomePASS, "")
		requireCase(t, r, "nested", OutcomePASS, "")
		assertNoOwnedResources(t, r.RunID)
	}
	if reports[0].RunID == reports[1].RunID {
		t.Fatal("concurrent runs shared an identity")
	}
}
func TestIntegrationSignalInterruption(t *testing.T) {
	binary := os.Getenv("UNPACKPROOF_CLI")
	if binary == "" {
		t.Fatal("set UNPACKPROOF_CLI to the host binary")
	}
	out := integrationOut(t, "signal")
	cfg := integrationConfig()
	cfg.Command = []string{"python", "-c", "import time;time.sleep(30)"}
	cfg.Limits.Timeout.Duration = 20 * time.Second
	configPath := filepath.Join(out, "config.json")
	if err := SaveJSON(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "run", "--config", configPath, "--guest", integrationGuest(t), "--out", out)
	var captured bytes.Buffer
	cmd.Stdout = &captured
	cmd.Stderr = &captured
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	var id string
	started := false
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(filepath.Join(out, "run.json")); err == nil {
			var r RunReport
			if json.Unmarshal(b, &r) == nil {
				id = r.RunID
			}
		}
		if id != "" {
			var b bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			err := docker(ctx, &b, nil, "ps", "-q", "--filter", "label=org.unpackproof.run="+id, "--filter", "name=-target")
			cancel()
			if err == nil && strings.TrimSpace(b.String()) != "" {
				started = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !started {
		t.Fatal("target did not start")
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("interrupted CLI returned success")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("CLI did not finish bounded cleanup")
	}
	r := readRun(t, out)
	requireCase(t, r, "file", OutcomeUNRESOLVED, "execution-interrupted")
	assertNoOwnedResources(t, id)
}

func TestIntegrationCleanupOnlyOwnsItsLabels(t *testing.T) {
	owned, _ := newRunID()
	foreign, _ := newRunID()
	names := []string{"unpackproof-" + owned + "-ownership", "unpackproof-" + foreign + "-ownership"}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for i, id := range []string{owned, foreign} {
		if err := docker(ctx, nil, nil, "volume", "create", "--label", "org.unpackproof.run="+id, "--label", "org.unpackproof.case=ownership", names[i]); err != nil {
			t.Fatal(err)
		}
		defer docker(context.Background(), nil, nil, "volume", "rm", names[i])
	}
	r := dockerRunner{runID: owned}
	if cr := r.cleanupCase("ownership"); !cr.OK {
		t.Fatal(cr.Error)
	}
	assertNoOwnedResources(t, owned)
	if err := docker(ctx, nil, nil, "volume", "inspect", names[1]); err != nil {
		t.Fatal("cleanup removed foreign volume", err)
	}
}
func TestIntegrationReportsSavedBeforeCleanupAndWriteFailure(t *testing.T) {
	realDocker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	witness := filepath.Join(dir, "witness")
	out := integrationOut(t, "persistence")
	// The wrapper delegates to the real Docker CLI. At the first deletion it
	// verifies that durable evidence and provenance already exist on disk.
	dockerPath, _ := json.Marshal(realDocker)
	reportPath, _ := json.Marshal(filepath.Join(out, "run.json"))
	witnessPath, _ := json.Marshal(witness)
	wrapper := fmt.Sprintf(`#!/usr/bin/env python3
import json,subprocess,sys
if sys.argv[1]=='rm':
 for container in sys.argv[2:]:
  if container.startswith('-'): continue
  host=json.loads(subprocess.check_output([%s,'inspect',container,'--format','{{json .HostConfig}}']))
  assert host['LogConfig']['Type']=='none' and host['Memory']>0 and host['PidsLimit']>0
 with open(%s) as f: report=json.load(f)
 assert report['image']['id'] and report['config']['command']
 assert report['cases'][-1]['outcome'] and report['cases'][-1]['observed']['root']
 assert not report['cases'][-1]['cleanup']['attempted']
 with open(%s,'w') as f: f.write('evidence saved')
sys.exit(subprocess.call([%s]+sys.argv[1:]))
`, dockerPath, reportPath, witnessPath, dockerPath)
	p := filepath.Join(dir, "docker")
	if err := os.WriteFile(p, []byte(wrapper), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := os.Mkdir(filepath.Join(out, "file.json"), 0755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	err = Run(ctx, integrationConfig(), integrationGuest(t), out, &bytes.Buffer{})
	if err == nil {
		t.Fatal("case report write failure returned success")
	}
	r := readRun(t, out)
	if len(r.Cases) != 1 || r.Cases[0].Outcome != OutcomePASS || r.Cases[0].ReportError == "" || !r.Cases[0].Cleanup.OK {
		t.Fatalf("lost verdict or persistence error: %#v", r.Cases)
	}
	if _, err := os.Stat(witness); err != nil {
		t.Fatal("cleanup preceded saved evidence", err)
	}
	assertNoOwnedResources(t, r.RunID)
}
func TestIntegrationRecoveryAfterReportFilesystemFailure(t *testing.T) {
	for _, recoveryAvailable := range []bool{true, false} {
		name := "recovery-succeeds"
		if !recoveryAvailable {
			name = "all-storage-unavailable"
		}
		t.Run(name, func(t *testing.T) {
			realDocker, err := exec.LookPath("docker")
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			out := integrationOut(t, "lost-output")
			recoveryDir := filepath.Join(dir, "recovery")
			if recoveryAvailable {
				err = os.Mkdir(recoveryDir, 0700)
			} else {
				err = os.WriteFile(recoveryDir, nil, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("TMPDIR", recoveryDir)
			witness := filepath.Join(dir, "before-cleanup.json")
			dockerPath, _ := json.Marshal(realDocker)
			outputPath, _ := json.Marshal(out)
			witnessPath, _ := json.Marshal(witness)
			wrapper := fmt.Sprintf(`#!/usr/bin/env python3
import glob,json,os,subprocess,sys
out=%s
if sys.argv[1]=='rm' and os.path.isdir(os.environ['TMPDIR']):
 paths=glob.glob(os.path.join(os.environ['TMPDIR'],'unpackproof-recovery-*','run.json'))
 assert len(paths)==1
 with open(paths[0]) as f: report=json.load(f)
 assert report['cases'][-1]['observed']['root']
 assert not report['cases'][-1]['cleanup']['attempted']
 with open(%s,'w') as f: json.dump(report,f)
code=subprocess.call([%s]+sys.argv[1:])
if sys.argv[1]=='start' and os.path.isdir(out):
 os.rename(out,out+'.initial')
 with open(out,'w') as f: f.write('filesystem unavailable')
sys.exit(code)
`, outputPath, witnessPath, dockerPath)
			if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(wrapper), 0755); err != nil {
				t.Fatal(err)
			}
			originalPATH := os.Getenv("PATH")
			t.Setenv("PATH", dir+string(os.PathListSeparator)+originalPATH)
			cfg := integrationConfig()
			cfg.Cases = []string{"file", "nested"}
			configPath := filepath.Join(dir, "config.json")
			if err := SaveJSON(configPath, cfg); err != nil {
				t.Fatal(err)
			}
			binary := os.Getenv("UNPACKPROOF_CLI")
			if binary == "" {
				t.Fatal("set UNPACKPROOF_CLI to the host binary")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			var human bytes.Buffer
			cmd := exec.CommandContext(ctx, binary, "run", "--config", configPath, "--guest", integrationGuest(t), "--out", out)
			cmd.Stdout, cmd.Stderr = &human, &human
			var exitErr *exec.ExitError
			if err := cmd.Run(); !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || ctx.Err() != nil {
				t.Fatalf("expected CLI exit 1 on persistence failure: %v %s", err, human.String())
			}
			initial := readRun(t, out+".initial")
			if recoveryAvailable {
				paths, err := filepath.Glob(filepath.Join(recoveryDir, "unpackproof-recovery-*", "run.json"))
				if err != nil || len(paths) != 1 {
					t.Fatalf("missing recovery checkpoint: %v %v", paths, err)
				}
				r := readRun(t, filepath.Dir(paths[0]))
				if len(r.Cases) != 1 || r.Cases[0].Outcome != OutcomePASS || r.Cases[0].ReportError == "" || !r.Cases[0].Cleanup.OK || r.Cases[0].RecoveryReport != paths[0] || r.FinishedAt.IsZero() || r.Image.ID == "" || len(r.Errors) == 0 {
					t.Fatalf("incomplete recovery report or further cases executed: %#v", r)
				}
				data, err := os.ReadFile(witness)
				if err != nil {
					t.Fatal("cleanup happened without saved evidence", err)
				}
				var before RunReport
				if err := json.Unmarshal(data, &before); err != nil || len(before.Cases) != 1 || before.Cases[0].Cleanup.Attempted || len(before.Cases[0].Observed.Objects) != 1 || before.Cases[0].Observed.Objects[0].SHA256 != r.Cases[0].Observed.Objects[0].SHA256 {
					t.Fatalf("evidence was not saved before cleanup: %s %v", data, err)
				}
				if !strings.Contains(human.String(), "recovery-report:") || !strings.Contains(human.String(), paths[0]) {
					t.Fatal("recovery path missing from human output", human.String())
				}
				assertNoOwnedResources(t, r.RunID)
			} else {
				defer func() {
					t.Setenv("PATH", originalPATH)
					runner := dockerRunner{runID: initial.RunID}
					if cleanup := runner.cleanupCase("file"); !cleanup.OK {
						t.Error(cleanup.Error)
					}
				}()
				if !strings.Contains(human.String(), "cleanup deferred") || !strings.Contains(human.String(), "recovery report persistence failed") {
					t.Fatal("total failure not reported", human.String())
				}
				var targets bytes.Buffer
				if err := docker(ctx, &targets, nil, "ps", "-q", "--filter", "label=org.unpackproof.run="+initial.RunID, "--filter", "name=-target"); err != nil || targets.Len() != 0 {
					t.Fatalf("running target retained: %q %v", targets.String(), err)
				}
				var volumes bytes.Buffer
				if err := docker(ctx, &volumes, nil, "volume", "ls", "-q", "--filter", "label=org.unpackproof.run="+initial.RunID); err != nil || len(strings.Fields(volumes.String())) != 1 {
					t.Fatalf("evidence removed or more cases executed: %q %v", volumes.String(), err)
				}
				var retained bytes.Buffer
				if err := docker(ctx, &retained, nil, "exec", "unpackproof-"+initial.RunID+"-file-keeper", "/unpackproof-guest", "snapshot", "--root", "/fixture", "--subpath", "destination"); err != nil {
					t.Fatal("keeper did not retain the tmpfs fixture", err)
				}
				var snapshot SnapshotResult
				spec, err := BuildCase("file", initial.Config.LinkPolicy, initial.Config.OverwritePolicy)
				if err != nil {
					t.Fatal(err)
				}
				if err := decodeSnapshot(retained.Bytes(), &snapshot); err != nil || !snapshot.Complete || len(snapshot.Objects) != 1 || snapshot.Objects[0].Path != "hello.txt" || snapshot.Objects[0].SHA256 != spec.Expected.Objects[0].SHA256 {
					t.Fatalf("retained fixture lost its evidence: %s %v", retained.String(), err)
				}
			}
		})
	}
}

func TestIntegrationCleanupHasDeadline(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "docker")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexec sleep 30\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	r := dockerRunner{runID: "no-resources"}
	start := time.Now()
	rep := r.cleanupCase("bounded")
	if rep.OK || !rep.Attempted || rep.Error == "" {
		t.Fatalf("cleanup failure ignored: %#v", rep)
	}
	if time.Since(start) > cleanupTimeout+3*time.Second {
		t.Fatal("cleanup was not bounded")
	}
}

func TestIntegrationNodePolicies(t *testing.T) {
	for _, policy := range []string{"replace", "preserve", "reject"} {
		t.Run(policy, func(t *testing.T) {
			cfg, err := LoadConfig(filepath.Join("..", "..", "configs", "node-tar.json"))
			if err != nil {
				t.Fatal(err)
			}
			cfg.Cases = []string{"duplicate", "existing"}
			cfg.OverwritePolicy = policy
			for i, arg := range cfg.Command {
				if arg == "--overwrite-policy" {
					cfg.Command[i+1] = policy
				}
			}
			r, err := runIntegration(t, cfg)
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"file", "duplicate", "existing"} {
				requireCase(t, r, id, OutcomePASS, "")
			}
		})
	}
	for _, policy := range []string{"skip", "reject"} {
		t.Run("links-"+policy, func(t *testing.T) {
			cfg, err := LoadConfig(filepath.Join("..", "..", "configs", "node-tar.json"))
			if err != nil {
				t.Fatal(err)
			}
			cfg.Cases = []string{"symlink", "hardlink", "links-denied"}
			cfg.LinkPolicy = policy
			for i, arg := range cfg.Command {
				if arg == "--link-policy" {
					cfg.Command[i+1] = policy
				}
			}
			r, err := runIntegration(t, cfg)
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"file", "symlink", "hardlink", "links-denied"} {
				requireCase(t, r, id, OutcomePASS, "")
			}
		})
	}
}
func TestIntegrationControlledAdapters(t *testing.T) {
	for _, tc := range []struct{ name, id, finding string }{
		{"controlled-noop", "file", "missing-object"},
		{"controlled-reject-all", "file", "unexpected-exit-code"},
		{"controlled-skip-normal", "file", "missing-object"},
		{"controlled-wrong-bytes", "file", "wrong-content"},
		{"controlled-overwrite-violate", "existing", "wrong-content"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadConfig(filepath.Join("..", "..", "configs", tc.name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			r, err := runIntegration(t, cfg)
			if err == nil {
				t.Fatal("controlled broken adapter passed")
			}
			requireCase(t, r, tc.id, OutcomeFAIL, tc.finding)
		})
	}
}

func TestIntegrationOOMIsInfrastructureError(t *testing.T) {
	cfg := integrationConfig()
	cfg.Cases = []string{"truncated"}
	cfg.Limits.Memory = "64m"
	cfg.Command = []string{"python", "-c", `import json,tarfile
case=json.load(open('/fixture/scratch/case.json'))['id']
if case=='file':
 tarfile.open('/fixture/input/archive.tar').extractall('/fixture/destination',filter='data')
else:
 data=bytearray(128*1024*1024)
`}
	r, err := runIntegration(t, cfg)
	if err == nil {
		t.Fatal("OOM passed as an expected archive rejection")
	}
	requireCase(t, r, "file", OutcomePASS, "")
	c := requireCase(t, r, "truncated", OutcomeInfrastructureError, "infrastructure-target")
	if c.Execution.Disposition != "resource-limit" {
		t.Fatalf("OOM classification lost: %#v", c.Execution)
	}
	cfg = integrationConfig()
	cfg.Cases = []string{"truncated"}
	cfg.Command = []string{"python", "-c", "raise SystemExit(137)"}
	r, err = runIntegration(t, cfg)
	if err == nil {
		t.Fatal("positive control passed")
	}
	c = requireCase(t, r, "truncated", OutcomePASS, "")
	if c.Execution.Disposition != "completed" {
		t.Fatal("ordinary exit 137 misclassified as OOM")
	}
}
func TestIntegrationRejectsImageVolumes(t *testing.T) {
	id, _ := newRunID()
	name := "unpackproof-image-test-" + id
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := docker(ctx, nil, nil, "create", "--name", name, "unpackproof/python-tarfile:0.1"); err != nil {
		t.Fatal(err)
	}
	defer docker(context.Background(), nil, nil, "rm", "-f", name)
	var image bytes.Buffer
	if err := docker(ctx, &image, nil, "commit", "--change", "VOLUME /data", name); err != nil {
		t.Fatal(err)
	}
	imageID := strings.TrimSpace(image.String())
	defer docker(context.Background(), nil, nil, "image", "rm", imageID)
	cfg := integrationConfig()
	cfg.Image = imageID
	r, err := runIntegration(t, cfg)
	if err == nil || !strings.Contains(err.Error(), "VOLUME") || len(r.Cases) != 0 {
		t.Fatalf("image with unbounded volumes accepted: %v %#v", err, r)
	}
}
