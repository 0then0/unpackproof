package up

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const cleanupTimeout = 10 * time.Second
const observationTimeout = 20 * time.Second

type limitBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.buf.Len()
	if remaining < len(p) {
		b.truncated = true
	}
	if remaining > 0 {
		n := len(p)
		if n > remaining {
			n = remaining
		}
		b.buf.Write(p[:n])
	}
	return len(p), nil
}
func (b *limitBuffer) String() string { return b.buf.String() }

type dockerRunner struct {
	cfg       Config
	guestPath string
	runID     string
	report    *RunReport
}

func newRunID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func Run(ctx context.Context, cfg Config, guestPath, outDir string, human io.Writer) error {
	cfg, err := normalizeConfig(cfg)
	if err != nil {
		return err
	}
	absGuest, err := filepath.Abs(guestPath)
	if err != nil {
		return err
	}
	if st, err := os.Stat(absGuest); err != nil {
		return fmt.Errorf("guest binary: %w", err)
	} else if st.IsDir() {
		return errors.New("guest binary path is a directory")
	}
	runID, err := newRunID()
	if err != nil {
		return err
	}
	report := RunReport{SchemaVersion: "unpackproof.report.v1", RunID: runID, Config: cfg, StartedAt: time.Now().UTC(), ConfigName: cfg.Name, Limitations: Limitations()}
	r := &dockerRunner{cfg: cfg, guestPath: absGuest, runID: runID, report: &report}
	report.Image, err = r.inspectImage(ctx)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		report.FinishedAt = time.Now().UTC()
		return errors.Join(err, SaveJSON(filepath.Join(outDir, "run.json"), report))
	}
	// Establish that reports can be persisted before allocating resources.
	if err := SaveJSON(filepath.Join(outDir, "run.json"), report); err != nil {
		return fmt.Errorf("save initial report: %w", err)
	}
	if len(cfg.TargetVersionCommand) > 0 {
		report.TargetVersion, err = r.targetVersion(ctx)
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
		}
	}
	hadBad := len(report.Errors) > 0
	for _, id := range cfg.Cases {
		if ctx.Err() != nil {
			break
		}
		cr := r.runCase(ctx, id, outDir)
		fmt.Fprintln(human, HumanCase(cr))
		if cr.Outcome != OutcomePASS || cr.ReportError != "" || !cr.Cleanup.OK {
			hadBad = true
		}
	}
	if ctx.Err() != nil {
		report.Errors = append(report.Errors, ctx.Err().Error())
		hadBad = true
	}
	report.FinishedAt = time.Now().UTC()
	if err := SaveJSON(filepath.Join(outDir, "run.json"), report); err != nil {
		return fmt.Errorf("save run report: %w", err)
	}
	if hadBad {
		return errors.New("run did not pass; see findings, report errors and cleanup status")
	}
	return nil
}

func (r *dockerRunner) runCase(ctx context.Context, id, outDir string) CaseReport {
	spec, err := BuildCase(id, r.cfg.LinkPolicy, r.cfg.OverwritePolicy)
	cr := CaseReport{SchemaVersion: "unpackproof.case-report.v1", Case: spec, Expected: spec.Expected, Image: r.report.Image, TargetVersion: r.report.TargetVersion, Limitations: Limitations()}
	finish := func(cr CaseReport) CaseReport { return r.finishWithCleanup(id, outDir, cr) }
	if err != nil {
		return finish(infraReport(cr, "case-build", err))
	}
	vol := "unpackproof-" + r.runID + "-" + id
	if err := docker(ctx, nil, nil, "volume", "create", "--driver", "local", "--opt", "type=tmpfs", "--opt", "device=tmpfs", "--opt", "o=size="+r.cfg.Limits.StorageTmpfs+",mode=1777", "--label", "org.unpackproof.run="+r.runID, "--label", "org.unpackproof.case="+id, vol); err != nil {
		return finish(infraReport(cr, "volume-create", err))
	}
	if err := r.startKeeper(ctx, id, vol); err != nil {
		return finish(infraReport(cr, "keeper-start", err))
	}
	if err := r.guest(ctx, id, vol, "setup", "--root", "/fixture", "--case", id, "--link-policy", r.cfg.LinkPolicy, "--overwrite-policy", r.cfg.OverwritePolicy); err != nil {
		return finish(infraReport(cr, "setup", err))
	}
	if err := r.snapshot(ctx, id, vol, "protected", &cr.ProtectedBefore); err != nil {
		return finish(infraReport(cr, "snapshot-protected-before", err))
	}
	cr.Execution = r.execute(ctx, id, vol, r.cfg.Command)
	// Observation and cleanup remain possible after target timeout or interruption.
	observeCtx, cancel := context.WithTimeout(context.Background(), observationTimeout)
	defer cancel()
	if err := r.snapshot(observeCtx, id, vol, "destination", &cr.Observed); err != nil {
		return finish(infraReport(cr, "snapshot-destination", err))
	}
	if err := r.snapshot(observeCtx, id, vol, "protected", &cr.Protected); err != nil {
		return finish(infraReport(cr, "snapshot-protected", err))
	}
	comp := Compare(spec, cr.Observed, cr.ProtectedBefore, cr.Protected, cr.Execution.ExitCode, cr.Execution.TimedOut)
	cr.Findings = comp.Findings
	cr.Completeness = "complete"
	if !comp.Complete {
		cr.Completeness = "incomplete"
	}
	switch {
	case cr.Execution.Interrupted:
		cr.Outcome = OutcomeUNRESOLVED
		cr.Findings = append(cr.Findings, Finding{ID: "execution-interrupted", Message: "target execution was interrupted"})
	case cr.Execution.Error != "":
		cr.Outcome = OutcomeInfrastructureError
		cr.Findings = append(cr.Findings, Finding{ID: "infrastructure-target", Message: cr.Execution.Error})
	case cr.Execution.TimedOut || !comp.Complete:
		cr.Outcome = OutcomeUNRESOLVED
	case len(comp.Findings) > 0:
		cr.Outcome = OutcomeFAIL
	default:
		cr.Outcome = OutcomePASS
	}
	return finish(cr)
}

func (r *dockerRunner) finishWithCleanup(id, outDir string, cr CaseReport) CaseReport {
	if cr.Outcome == "" {
		cr.Outcome = OutcomeInfrastructureError
	}
	index := len(r.report.Cases)
	r.report.Cases = append(r.report.Cases, cr)
	saveCase := func() {
		if err := SaveJSON(filepath.Join(outDir, id+".json"), cr); err != nil {
			cr.ReportError = errors.Join(errors.New("case report persistence failed"), err).Error()
		}
		r.report.Cases[index] = cr
	}
	// Both the standalone case and the run checkpoint contain the verdict and
	// evidence before any owned container or volume is removed.
	saveCase()
	if err := SaveJSON(filepath.Join(outDir, "run.json"), r.report); err != nil {
		cr.ReportError = errors.Join(errors.New("run checkpoint persistence failed"), err).Error()
	}
	cr.Cleanup = r.cleanupCase(id)
	saveCase()
	if err := SaveJSON(filepath.Join(outDir, "run.json"), r.report); err != nil {
		cr.ReportError = errors.Join(errors.New("run checkpoint persistence failed"), err).Error()
		r.report.Cases[index] = cr
	}
	return cr
}

func (r *dockerRunner) cleanupCase(id string) CleanupReport {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	rep := CleanupReport{Attempted: true, OK: true}
	filters := []string{"--filter", "label=org.unpackproof.run=" + r.runID, "--filter", "label=org.unpackproof.case=" + id}
	var failures []error
	var out bytes.Buffer
	args := append([]string{"ps", "-aq"}, filters...)
	if err := docker(ctx, &out, nil, args...); err != nil {
		failures = append(failures, err)
	} else if ids := strings.Fields(out.String()); len(ids) > 0 {
		if err := docker(ctx, nil, nil, append([]string{"rm", "-f"}, ids...)...); err != nil {
			failures = append(failures, err)
		}
	}
	out.Reset()
	args = append([]string{"volume", "ls", "-q"}, filters...)
	if err := docker(ctx, &out, nil, args...); err != nil {
		failures = append(failures, err)
	} else if volumes := strings.Fields(out.String()); len(volumes) > 0 {
		if err := docker(ctx, nil, nil, append([]string{"volume", "rm"}, volumes...)...); err != nil {
			failures = append(failures, err)
		}
	}
	if err := errors.Join(failures...); err != nil {
		rep.OK = false
		rep.Error = err.Error()
	}
	return rep
}

func infraReport(cr CaseReport, stage string, err error) CaseReport {
	cr.Outcome = OutcomeInfrastructureError
	cr.Findings = append(cr.Findings, Finding{ID: "infrastructure-" + stage, Message: err.Error()})
	cr.Completeness = "incomplete"
	return cr
}

func (r *dockerRunner) runtimeArgs(id, user string) []string {
	return []string{"--network", "none", "--user", user, "--read-only", "--log-driver", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", fmt.Sprint(r.cfg.Limits.PIDs), "--memory", r.cfg.Limits.Memory, "--memory-swap", r.cfg.Limits.Memory, "--cpus", r.cfg.Limits.CPUs, "--tmpfs", "/tmp:size=" + r.cfg.Limits.StorageTmpfs + ",mode=1777", "--label", "org.unpackproof.run=" + r.runID, "--label", "org.unpackproof.case=" + id}
}
func (r *dockerRunner) image() string { return r.report.Image.ID }

func (r *dockerRunner) guest(ctx context.Context, id, vol string, args ...string) error {
	command := []string{"run", "--rm", "--name", vol + "-" + args[0]}
	command = append(command, r.runtimeArgs(id, "0:0")...)
	command = append(command, "--cap-add", "DAC_OVERRIDE")
	if args[0] == "setup" {
		command = append(command, "--cap-add", "CHOWN", "--cap-add", "FOWNER")
	}
	command = append(command, "--workdir", "/", "-v", vol+":/fixture", "-v", r.guestPath+":/unpackproof-guest:ro", "--entrypoint", "/unpackproof-guest", r.image())
	return docker(ctx, nil, nil, append(command, args...)...)
}
func (r *dockerRunner) startKeeper(ctx context.Context, id, vol string) error {
	command := []string{"run", "-d", "--name", vol + "-keeper"}
	command = append(command, r.runtimeArgs(id, "10000:10000")...)
	command = append(command, "--workdir", "/", "-v", vol+":/fixture", "-v", r.guestPath+":/unpackproof-guest:ro", "--entrypoint", "/unpackproof-guest", r.image(), "hold", "--seconds", fmt.Sprint(int64(r.cfg.Limits.Timeout.Duration/time.Second)+120))
	return docker(ctx, nil, nil, command...)
}
func (r *dockerRunner) snapshot(ctx context.Context, id, vol, subpath string, v *SnapshotResult) error {
	var out, errb limitBuffer
	out.limit = 2 << 20
	errb.limit = 4096
	args := []string{"run", "--rm", "--name", vol + "-snapshot-" + subpath}
	args = append(args, r.runtimeArgs(id, "0:0")...)
	args = append(args, "--cap-add", "DAC_OVERRIDE", "--workdir", "/", "-v", vol+":/fixture", "-v", r.guestPath+":/unpackproof-guest:ro", "--entrypoint", "/unpackproof-guest", r.image(), "snapshot", "--root", "/fixture", "--subpath", subpath)
	if err := docker(ctx, &out, &errb, args...); err != nil {
		return fmt.Errorf("%w: %s", err, errb.String())
	}
	if out.truncated {
		return errors.New("snapshot output exceeded limit")
	}
	return decodeSnapshot([]byte(out.String()), v)
}
func decodeSnapshot(data []byte, v *SnapshotResult) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return errors.New("snapshot must contain exactly one JSON object")
	}
	return ValidateSnapshot(*v)
}

// Container creation, attachment and State inspection distinguish invocation
// failures from genuine target exits, including target exits 125/126/127.
func (r *dockerRunner) execute(ctx context.Context, id, vol string, argv []string) ExecutionReport {
	start := time.Now()
	rep := ExecutionReport{ExitCode: -1, Disposition: "infrastructure-error"}
	name := "unpackproof-" + r.runID + "-" + id + "-target"
	tctx, cancel := context.WithTimeout(ctx, r.cfg.Limits.Timeout.Duration)
	defer cancel()
	args := []string{"create", "--name", name}
	args = append(args, r.runtimeArgs(id, "10000:10000")...)
	if vol != "" {
		args = append(args, "-v", vol+":/fixture", "-v", r.guestPath+":/unpackproof-guest:ro", "--workdir", "/fixture/destination")
	} else {
		args = append(args, "--workdir", "/")
	}
	cmdv := replacePlaceholders(argv)
	args = append(args, "--entrypoint", cmdv[0], r.image())
	args = append(args, cmdv[1:]...)
	var created bytes.Buffer
	err := docker(tctx, &created, nil, args...)
	if err == nil {
		var stdout, stderr limitBuffer
		stdout.limit = r.cfg.Limits.MaxCapturedOutput
		stderr.limit = r.cfg.Limits.MaxCapturedOutput
		err = docker(tctx, &stdout, &stderr, "start", "--attach", name)
		rep.Stdout, rep.Stderr = stdout.String(), stderr.String()
		rep.StdoutTruncated, rep.StderrTruncated = stdout.truncated, stderr.truncated
	}
	rep.DurationMillis = time.Since(start).Milliseconds()
	if tctx.Err() != nil {
		rep.TimedOut = tctx.Err() == context.DeadlineExceeded
		rep.Interrupted = !rep.TimedOut
		rep.Disposition = "interrupted"
		if rep.TimedOut {
			rep.Disposition = "timed-out"
		}
		// Freeze target effects before snapshotting, while retaining its state and
		// fixture until the evidence is saved. Cleanup later removes the container.
		stopCtx, stopCancel := context.WithTimeout(context.Background(), cleanupTimeout)
		stopErr := docker(stopCtx, nil, nil, "kill", name)
		stopCancel()
		if stopErr != nil {
			rep.Error = stopErr.Error()
		}
		return rep
	}
	if created.Len() == 0 {
		rep.Error = fmt.Sprintf("create target: %v", err)
		return rep
	}
	var state struct {
		Status    string
		Running   bool
		ExitCode  int
		Error     string
		StartedAt string
		OOMKilled bool
	}
	var out bytes.Buffer
	inspectCtx, inspectCancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer inspectCancel()
	if inspectErr := docker(inspectCtx, &out, nil, "inspect", name, "--format", "{{json .State}}"); inspectErr != nil {
		rep.Error = inspectErr.Error()
		return rep
	}
	if decodeErr := json.Unmarshal(out.Bytes(), &state); decodeErr != nil {
		rep.Error = decodeErr.Error()
		return rep
	}
	if state.OOMKilled {
		rep.Disposition = "resource-limit"
		rep.ExitCode = state.ExitCode
		rep.Error = "target was killed by the memory limit"
		return rep
	}
	if state.Error != "" || state.Status != "exited" || state.Running || strings.HasPrefix(state.StartedAt, "0001-") {
		rep.Error = fmt.Sprintf("target did not complete: status=%s runtime_error=%s attach_error=%v", state.Status, state.Error, err)
		return rep
	}
	rep.Disposition = "completed"
	rep.ExitCode = state.ExitCode
	return rep
}

func replacePlaceholders(xs []string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		x = strings.ReplaceAll(x, "{archive}", "/fixture/input/archive.tar")
		x = strings.ReplaceAll(x, "{destination}", "/fixture/destination")
		out[i] = strings.ReplaceAll(x, "{scratch}", "/fixture/scratch")
	}
	return out
}
func docker(ctx context.Context, stdout, stderr io.Writer, args ...string) error {
	var diagnostic limitBuffer
	diagnostic.limit = 4096
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.WaitDelay = 2 * time.Second
	cmd.Stdout = stdout
	if stderr == nil {
		cmd.Stderr = &diagnostic
	} else {
		cmd.Stderr = stderr
	}
	err := cmd.Run()
	if err != nil && diagnostic.String() != "" {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(diagnostic.String()))
	}
	return err
}
func (r *dockerRunner) inspectImage(ctx context.Context) (ImageReport, error) {
	rep := ImageReport{Reference: r.cfg.Image}
	var out bytes.Buffer
	if err := docker(ctx, &out, nil, "image", "inspect", r.cfg.Image, "--format", "{{json .}}"); err != nil {
		return rep, err
	}
	var data struct {
		ID          string                                       `json:"Id"`
		RepoDigests []string                                     `json:"RepoDigests"`
		Config      struct{ Volumes map[string]json.RawMessage } `json:"Config"`
	}
	if err := json.Unmarshal(out.Bytes(), &data); err != nil {
		return rep, err
	}
	if data.ID == "" {
		return rep, errors.New("image identity is missing")
	}
	rep.ID, rep.RepoDigests = data.ID, data.RepoDigests
	if len(data.Config.Volumes) > 0 {
		return rep, errors.New("image declares VOLUME mounts; prepare an image without anonymous volumes so writable storage stays bounded")
	}
	return rep, nil
}
func (r *dockerRunner) targetVersion(ctx context.Context) (string, error) {
	rep := r.execute(ctx, "version", "", r.cfg.TargetVersionCommand)
	cleanup := r.cleanupCase("version")
	if rep.Disposition != "completed" || rep.ExitCode != 0 || !cleanup.OK {
		return strings.TrimSpace(rep.Stdout), fmt.Errorf("target version failed: disposition=%s exit=%d error=%s cleanup=%s", rep.Disposition, rep.ExitCode, rep.Error, cleanup.Error)
	}
	return strings.TrimSpace(rep.Stdout), nil
}
