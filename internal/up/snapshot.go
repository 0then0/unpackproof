package up

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

type SnapshotLimit struct {
	MaxEntries   int
	MaxFileBytes int64
}

type SnapshotResult struct {
	RootMissing bool             `json:"root_missing,omitempty"`
	FixtureRoot *ObservedObject  `json:"fixture_root,omitempty"`
	Root        *ObservedObject  `json:"root"`
	Objects     []ObservedObject `json:"objects"`
	Complete    bool             `json:"complete"`
	Incomplete  string           `json:"incomplete_reason,omitempty"`
}

type ObservedObject struct {
	Path       string `json:"path"`
	Type       string `json:"type"`
	Size       int64  `json:"size,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Mode       string `json:"mode,omitempty"`
	LinkTarget string `json:"link_target,omitempty"`
	Dev        uint64 `json:"dev,omitempty"`
	Ino        uint64 `json:"ino,omitempty"`
}

func Snapshot(root string, limit SnapshotLimit) (out SnapshotResult, err error) {
	defer func() {
		if err != nil {
			out.Complete = false
			out.Incomplete = err.Error()
		}
	}()
	if limit.MaxEntries <= 0 {
		limit.MaxEntries = 2048
	}
	if limit.MaxFileBytes <= 0 {
		limit.MaxFileBytes = 8 << 20
	}
	out = SnapshotResult{Complete: true, Objects: []ObservedObject{}}
	info, err := os.Lstat(root)
	if err != nil {
		return out, err
	}
	rootObject := ObservedObject{Path: ".", Type: "dir", Mode: permissionString(info.Mode())}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		rootObject.Dev, rootObject.Ino = uint64(st.Dev), uint64(st.Ino)
	}
	out.Root = &rootObject
	if !info.IsDir() {
		rootObject.Type = "file"
		if info.Mode()&os.ModeSymlink != 0 {
			rootObject.Type = "symlink"
			rootObject.LinkTarget, err = os.Readlink(root)
		} else if !info.Mode().IsRegular() {
			rootObject.Type = "special"
		}
		return out, err
	}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		if len(out.Objects) >= limit.MaxEntries {
			out.Complete = false
			out.Incomplete = "max entries exceeded"
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		obj := ObservedObject{Path: filepath.ToSlash(rel), Mode: permissionString(info.Mode())}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			obj.Dev = uint64(st.Dev)
			obj.Ino = uint64(st.Ino)
		}
		switch {
		case info.Mode().IsRegular():
			obj.Type = "file"
			obj.Size = info.Size()
			if info.Size() > limit.MaxFileBytes {
				out.Complete = false
				out.Incomplete = "max file bytes exceeded"
				break
			}
			sum, err := hashFile(path)
			if err != nil {
				return err
			}
			obj.SHA256 = sum
		case info.IsDir():
			obj.Type = "dir"
		case info.Mode()&os.ModeSymlink != 0:
			obj.Type = "symlink"
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			obj.LinkTarget = target
		default:
			obj.Type = "special"
			out.Complete = false
			out.Incomplete = "special file observed"
		}
		out.Objects = append(out.Objects, obj)
		return nil
	})
	sort.Slice(out.Objects, func(i, j int) bool { return out.Objects[i].Path < out.Objects[j].Path })
	return out, err
}

// SnapshotFixture observes a direct child of an accessible fixture. Only the
// initial Lstat of that child can establish absence; errors during traversal,
// hashing, fixture access or identity checks remain observation failures.
func SnapshotFixture(fixture, subpath string, limit SnapshotLimit) (SnapshotResult, error) {
	if !oneOf(subpath, "destination", "protected") {
		return SnapshotResult{}, errors.New("snapshot requires destination or protected")
	}
	before, err := observeFixtureRoot(fixture)
	if err != nil {
		return SnapshotResult{}, fmt.Errorf("fixture unavailable: %w", err)
	}
	root := filepath.Join(fixture, subpath)
	out, snapshotErr := Snapshot(root, limit)
	var pathErr *os.PathError
	missing := out.Root == nil && errors.As(snapshotErr, &pathErr) &&
		pathErr.Op == "lstat" && pathErr.Path == root && errors.Is(pathErr.Err, syscall.ENOENT)
	if snapshotErr != nil && !missing {
		return out, snapshotErr
	}
	after, err := observeFixtureRoot(fixture)
	if err != nil || !sameIdentity(before, after) {
		out.Complete = false
		return out, fmt.Errorf("fixture unavailable or replaced during observation: %v", err)
	}
	out.FixtureRoot = after
	if missing {
		out.RootMissing = true
		out.Complete = true
		out.Incomplete = ""
	}
	return out, nil
}

func observeFixtureRoot(root string) (*ObservedObject, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("fixture root must be a directory, not a symlink")
	}
	f, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("fixture identity changed while opening directory")
	}
	// Check directory access without an unbounded listing of target output.
	if _, err := f.Readdirnames(1); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	st, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || st.Dev == 0 || st.Ino == 0 {
		return nil, errors.New("fixture identity unavailable")
	}
	return &ObservedObject{Path: ".", Type: "dir", Dev: uint64(st.Dev), Ino: uint64(st.Ino)}, nil
}

func sameIdentity(a, b *ObservedObject) bool {
	return a != nil && b != nil && a.Type == "dir" && b.Type == "dir" &&
		a.Dev != 0 && a.Ino != 0 && a.Dev == b.Dev && a.Ino == b.Ino
}

func permissionString(mode os.FileMode) string {
	bits := uint32(mode.Perm())
	if mode&os.ModeSetuid != 0 {
		bits |= 04000
	}
	if mode&os.ModeSetgid != 0 {
		bits |= 02000
	}
	if mode&os.ModeSticky != 0 {
		bits |= 01000
	}
	return fmt.Sprintf("%04o", bits)
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type ProbeResult struct {
	Hardlinks bool   `json:"hardlinks"`
	Error     string `json:"error,omitempty"`
}

func Probe(root string) ProbeResult {
	if err := os.MkdirAll(root, 0777); err != nil {
		return ProbeResult{Error: err.Error()}
	}
	a := filepath.Join(root, "probe-a")
	b := filepath.Join(root, "probe-b")
	_ = os.Remove(a)
	_ = os.Remove(b)
	if err := os.WriteFile(a, []byte("probe"), 0666); err != nil {
		return ProbeResult{Error: err.Error()}
	}
	if err := os.Link(a, b); err != nil {
		return ProbeResult{Hardlinks: false, Error: err.Error()}
	}
	_ = os.Remove(a)
	_ = os.Remove(b)
	return ProbeResult{Hardlinks: true}
}

type Finding struct {
	ID      string `json:"id"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

type Comparison struct {
	Findings []Finding `json:"findings"`
	Complete bool      `json:"complete"`
}

func Compare(spec CaseSpec, observed, protectedBefore, protected SnapshotResult, exitCode int, timedOut bool) Comparison {
	c := Comparison{Complete: observed.Complete && protectedBefore.Complete && protected.Complete}
	if observed.RootMissing {
		c.add("missing-destination-root", ".", "required destination root is absent")
	} else if observed.Root == nil {
		c.Complete = false
		c.add("incomplete-observation", ".", "destination root was not observed")
	} else if observed.Root.Type != "dir" {
		c.add("wrong-root-type", ".", "destination root must remain a directory")
	}
	if !observed.Complete {
		c.add("incomplete-observation", "", observed.Incomplete)
	}
	if !protected.Complete {
		c.add("incomplete-protected-observation", "", protected.Incomplete)
	}
	if protectedBefore.Root == nil || protectedBefore.RootMissing {
		c.Complete = false
		c.add("incomplete-protected-baseline", "protected", "protected baseline root was not observed")
	}
	if timedOut {
		c.add("execution-timeout", "", "target exceeded configured timeout")
	}
	switch spec.Expected.Exit {
	case "zero":
		if exitCode != 0 && !timedOut {
			c.add("unexpected-exit-code", "", fmt.Sprintf("expected zero exit, got %d", exitCode))
		}
	case "nonzero":
		if exitCode == 0 && !timedOut {
			c.add("unexpected-exit-code", "", "expected nonzero exit, got 0")
		}
	}
	want := map[string]FSObject{}
	for _, obj := range spec.Expected.Objects {
		want[obj.Path] = obj
	}
	allow := map[string]bool{}
	for _, p := range spec.Expected.AllowPaths {
		allow[p] = true
	}
	got := map[string]ObservedObject{}
	for _, obj := range observed.Objects {
		got[obj.Path] = obj
	}
	for path, exp := range want {
		obs, ok := got[path]
		if !ok {
			c.add("missing-object", path, "expected object is missing")
			continue
		}
		if obs.Type != exp.Type {
			c.add("wrong-type", path, fmt.Sprintf("expected %s, got %s", exp.Type, obs.Type))
			continue
		}
		if exp.Mode != "" && obs.Mode != exp.Mode {
			c.add("wrong-permissions", path, fmt.Sprintf("expected mode %s, got %s", exp.Mode, obs.Mode))
		}
		if exp.Type == "file" {
			if obs.SHA256 != exp.SHA256 || obs.Size != exp.Size {
				c.add("wrong-content", path, "file content or size does not match expected bytes")
			}
			if exp.SameAs != "" {
				base, ok := got[exp.SameAs]
				if !ok {
					c.add("missing-link-target", path, "hardlink target missing")
				} else if base.Dev == 0 || base.Ino == 0 || base.Dev != obs.Dev || base.Ino != obs.Ino {
					c.add("wrong-link-identity", path, "hardlink does not share device/inode with target")
				}
			}
		}
		if exp.Type == "symlink" && obs.LinkTarget != exp.LinkTarget {
			c.add("wrong-link-target", path, fmt.Sprintf("expected target %q, got %q", exp.LinkTarget, obs.LinkTarget))
		}
	}
	for path := range got {
		if _, ok := want[path]; !ok && !allow[path] {
			c.add("unexpected-object", path, "object was not part of expected tree")
		}
	}
	if protected.RootMissing {
		c.add("missing-protected-root", "protected", "required protected root is absent")
	} else if protected.Root == nil {
		c.Complete = false
		c.add("incomplete-protected-observation", "protected", "protected root was not observed")
	} else if err := checkProtected(protectedBefore, protected); err != nil {
		c.add("protected-changed", "protected", err.Error())
	}
	sort.Slice(c.Findings, func(i, j int) bool {
		a, b := c.Findings[i], c.Findings[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Message < b.Message
	})
	return c
}

func (c *Comparison) add(id, path, msg string) {
	c.Findings = append(c.Findings, Finding{ID: id, Path: path, Message: msg})
}

func checkProtected(before, after SnapshotResult) error {
	if before.Root == nil || after.Root == nil || *before.Root != *after.Root {
		return errors.New("protected directory type, permissions or identity changed")
	}
	if len(before.Objects) != len(after.Objects) {
		return errors.New("protected tree changed")
	}
	want := make(map[string]ObservedObject, len(before.Objects))
	for _, obj := range before.Objects {
		want[obj.Path] = obj
	}
	for _, obj := range after.Objects {
		if expected, ok := want[obj.Path]; !ok || expected != obj {
			return fmt.Errorf("protected object changed: %q", obj.Path)
		}
	}
	return nil
}

// ValidateSnapshot rejects malformed evidence instead of treating absent or
// duplicated fields as an empty successful observation.
func ValidateSnapshot(s SnapshotResult) error {
	if s.FixtureRoot != nil && (s.FixtureRoot.Path != "." || !sameIdentity(s.FixtureRoot, s.FixtureRoot)) {
		return errors.New("invalid fixture identity")
	}
	if s.RootMissing {
		if s.Root != nil || len(s.Objects) != 0 || !s.Complete || s.Incomplete != "" || s.FixtureRoot == nil {
			return errors.New("missing root requires complete absence evidence and fixture identity")
		}
		return nil
	}
	if s.Root == nil || s.Root.Path != "." || !oneOf(s.Root.Type, "dir", "file", "symlink", "special") {
		return errors.New("snapshot root is missing or invalid")
	}
	seen := make(map[string]bool)
	for _, obj := range s.Objects {
		if obj.Path == "" || obj.Path == "." || filepath.IsAbs(obj.Path) || filepath.ToSlash(filepath.Clean(obj.Path)) != obj.Path || strings.HasPrefix(obj.Path, "../") || seen[obj.Path] {
			return fmt.Errorf("invalid or duplicate snapshot path %q", obj.Path)
		}
		seen[obj.Path] = true
		if !oneOf(obj.Type, "dir", "file", "symlink", "special") || obj.Size < 0 {
			return fmt.Errorf("invalid snapshot object %q", obj.Path)
		}
		if obj.Type == "file" && (s.Complete || obj.SHA256 != "") {
			if hash, err := hex.DecodeString(obj.SHA256); err != nil || len(hash) != sha256.Size {
				return fmt.Errorf("invalid file hash for %q", obj.Path)
			}
		}
	}
	if !s.Complete && s.Incomplete == "" {
		return errors.New("incomplete snapshot has no reason")
	}
	return nil
}
