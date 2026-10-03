package up

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	OutcomePASS                = "PASS"
	OutcomeFAIL                = "FAIL"
	OutcomeUNRESOLVED          = "UNRESOLVED"
	OutcomeInfrastructureError = "INFRASTRUCTURE_ERROR"
)

var fixedTime = time.Unix(1700000000, 0).UTC()

type CaseMeta struct {
	ID          string
	Description string
}

type CaseSpec struct {
	ID              string     `json:"id"`
	Description     string     `json:"description"`
	LinkPolicy      string     `json:"link_policy"`
	OverwritePolicy string     `json:"overwrite_policy"`
	Entries         []TarEntry `json:"entries"`
	InitialDest     []FSObject `json:"initial_destination,omitempty"`
	Expected        Expected   `json:"expected"`
	ArchiveSHA256   string     `json:"archive_sha256"`
	Truncated       bool       `json:"truncated,omitempty"`
}

type TarEntry struct {
	Path     string `json:"path"`
	Type     string `json:"type"`
	Data     string `json:"data,omitempty"`
	LinkName string `json:"link_name,omitempty"`
}

type FSObject struct {
	Path       string `json:"path"`
	Type       string `json:"type"`
	Size       int64  `json:"size,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Mode       string `json:"mode,omitempty"`
	LinkTarget string `json:"link_target,omitempty"`
	SameAs     string `json:"same_as,omitempty"`
}

type Expected struct {
	Exit       string     `json:"exit"`
	Objects    []FSObject `json:"objects"`
	AllowPaths []string   `json:"allow_paths,omitempty"`
}

func AllCases() []CaseMeta {
	return []CaseMeta{
		{"file", "ordinary file with known bytes"},
		{"nested", "nested directories and multiple files"},
		{"empty", "empty files and directories"},
		{"unicode", "Unicode names supported by the Linux environment"},
		{"pax", "long path emitted with PAX metadata"},
		{"duplicate", "duplicate member follows the overwrite policy"},
		{"existing", "existing destination file with explicit overwrite policy"},
		{"symlink", "internal symlink to an object inside destination"},
		{"hardlink", "internal hardlink identity"},
		{"links-denied", "link policy skip or rejection"},
		{"truncated", "truncated archive error handling"},
	}
}

func BuildCase(id, linkPolicy, overwritePolicy string) (CaseSpec, error) {
	if !oneOf(linkPolicy, "allow", "skip", "reject") {
		return CaseSpec{}, fmt.Errorf("invalid link policy %q", linkPolicy)
	}
	if !oneOf(overwritePolicy, "replace", "preserve", "reject") {
		return CaseSpec{}, fmt.Errorf("invalid overwrite policy %q", overwritePolicy)
	}
	c := CaseSpec{ID: id, LinkPolicy: linkPolicy, OverwritePolicy: overwritePolicy}
	c.Expected.Exit = "zero"
	switch id {
	case "file":
		c.Description = "ordinary file with known bytes"
		c.Entries = []TarEntry{{Path: "hello.txt", Type: "file", Data: "hello unpackproof\n"}}
		c.Expected.Objects = files("hello.txt", "hello unpackproof\n")
	case "nested":
		c.Description = "nested directories and multiple files"
		c.Entries = []TarEntry{
			{Path: "dir", Type: "dir"},
			{Path: "dir/a.txt", Type: "file", Data: "a\n"},
			{Path: "dir/sub", Type: "dir"},
			{Path: "dir/sub/b.txt", Type: "file", Data: "b\n"},
			{Path: "top.txt", Type: "file", Data: "top\n"},
		}
		c.Expected.Objects = []FSObject{
			dir("dir"), file("dir/a.txt", "a\n"), dir("dir/sub"), file("dir/sub/b.txt", "b\n"), file("top.txt", "top\n"),
		}
	case "empty":
		c.Description = "empty files and directories"
		c.Entries = []TarEntry{{Path: "empty-dir", Type: "dir"}, {Path: "empty.txt", Type: "file"}}
		c.Expected.Objects = []FSObject{dir("empty-dir"), file("empty.txt", "")}
	case "unicode":
		c.Description = "Unicode file names"
		c.Entries = []TarEntry{
			{Path: "unicode/пример.txt", Type: "file", Data: "privet\n"},
			{Path: "unicode/snowman-☃.txt", Type: "file", Data: "snow\n"},
		}
		c.Expected.Objects = []FSObject{dir("unicode"), file("unicode/пример.txt", "privet\n"), file("unicode/snowman-☃.txt", "snow\n")}
	case "pax":
		c.Description = "long path through PAX metadata"
		long := "long/" + strings.Repeat("segment-", 15) + "leaf.txt"
		c.Entries = []TarEntry{{Path: long, Type: "file", Data: "long pax path\n"}}
		c.Expected.Objects = []FSObject{dir("long"), file(long, "long pax path\n")}
	case "duplicate":
		c.Description = "duplicate member follows the overwrite policy"
		c.Entries = []TarEntry{
			{Path: "dupe.txt", Type: "file", Data: "first\n"},
			{Path: "dupe.txt", Type: "file", Data: "second\n"},
		}
		c.Expected.Objects = files("dupe.txt", "second\n")
		if overwritePolicy != "replace" {
			c.Expected.Objects = files("dupe.txt", "first\n")
			if overwritePolicy == "reject" {
				c.Expected.Exit = "nonzero"
			}
		}
	case "existing":
		c.Description = "existing destination overwrite policy"
		c.InitialDest = files("already.txt", "initial\n")
		c.Entries = []TarEntry{{Path: "already.txt", Type: "file", Data: "archive\n"}}
		switch overwritePolicy {
		case "replace":
			c.Expected.Objects = files("already.txt", "archive\n")
		case "preserve":
			c.Expected.Objects = files("already.txt", "initial\n")
		case "reject":
			c.Expected.Exit = "nonzero"
			c.Expected.Objects = files("already.txt", "initial\n")
		}
	case "symlink":
		c.Description = "internal symlink"
		c.Entries = []TarEntry{{Path: "target.txt", Type: "file", Data: "target\n"}, {Path: "link.txt", Type: "symlink", LinkName: "target.txt"}}
		if linkPolicy == "allow" {
			c.Expected.Objects = []FSObject{file("target.txt", "target\n"), symlink("link.txt", "target.txt")}
		} else {
			c.Expected.Objects = files("target.txt", "target\n")
			if linkPolicy == "reject" {
				c.Expected.Exit = "nonzero"
			}
		}
	case "hardlink":
		c.Description = "internal hardlink"
		c.Entries = []TarEntry{{Path: "original.txt", Type: "file", Data: "same inode\n"}, {Path: "hard.txt", Type: "hardlink", LinkName: "original.txt"}}
		if linkPolicy == "allow" {
			c.Expected.Objects = []FSObject{file("original.txt", "same inode\n"), hardfile("hard.txt", "same inode\n", "original.txt")}
		} else {
			c.Expected.Objects = files("original.txt", "same inode\n")
			if linkPolicy == "reject" {
				c.Expected.Exit = "nonzero"
			}
		}
	case "links-denied":
		if linkPolicy == "allow" {
			return CaseSpec{}, errors.New("links-denied requires link_policy skip or reject")
		}
		c.Description = "explicit forbidden links policy"
		c.Entries = []TarEntry{{Path: "blocked-link", Type: "symlink", LinkName: "target.txt"}, {Path: "blocked-hard", Type: "hardlink", LinkName: "target.txt"}}
		if linkPolicy == "reject" {
			c.Expected.Exit = "nonzero"
		}
	case "truncated":
		c.Description = "truncated archive reports extraction error"
		c.Truncated = true
		c.Expected.Exit = "nonzero"
		c.Expected.AllowPaths = []string{"partial.txt"}
	default:
		return CaseSpec{}, fmt.Errorf("unknown case %q", id)
	}
	sortFS(c.Expected.Objects)
	archive, err := ArchiveBytes(c)
	if err != nil {
		return CaseSpec{}, err
	}
	sum := sha256.Sum256(archive)
	c.ArchiveSHA256 = hex.EncodeToString(sum[:])
	return c, nil
}

func files(path, data string) []FSObject { return []FSObject{file(path, data)} }

func file(path, data string) FSObject {
	sum := sha256.Sum256([]byte(data))
	return FSObject{Path: path, Type: "file", Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Mode: "0644"}
}

func hardfile(path, data, sameAs string) FSObject {
	o := file(path, data)
	o.SameAs = sameAs
	return o
}

func dir(path string) FSObject { return FSObject{Path: path, Type: "dir", Mode: "0755"} }

func symlink(path, target string) FSObject {
	return FSObject{Path: path, Type: "symlink", LinkTarget: target, Mode: "0777"}
}

func sortFS(xs []FSObject) {
	sort.Slice(xs, func(i, j int) bool { return xs[i].Path < xs[j].Path })
}

func ArchiveBytes(c CaseSpec) ([]byte, error) {
	if c.Truncated {
		var b bytes.Buffer
		h := &tar.Header{Name: "partial.txt", Typeflag: tar.TypeReg, Mode: 0644, Size: 32, ModTime: fixedTime, Uid: 10000, Gid: 10000}
		if err := tar.NewWriter(&b).WriteHeader(h); err != nil {
			return nil, err
		}
		b.WriteString("short")
		return b.Bytes(), nil
	}
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range c.Entries {
		name := strings.TrimPrefix(filepath.Clean(e.Path), "/")
		if name == "." || strings.HasPrefix(name, "../") {
			return nil, fmt.Errorf("unsafe corpus path %q", e.Path)
		}
		h := &tar.Header{Name: name, ModTime: fixedTime, AccessTime: fixedTime, ChangeTime: fixedTime, Uid: 10000, Gid: 10000, Uname: "unpackproof", Gname: "unpackproof"}
		switch e.Type {
		case "file":
			h.Typeflag = tar.TypeReg
			h.Mode = 0644
			h.Size = int64(len(e.Data))
		case "dir":
			h.Typeflag = tar.TypeDir
			h.Mode = 0755
		case "symlink":
			h.Typeflag = tar.TypeSymlink
			h.Mode = 0777
			h.Linkname = e.LinkName
		case "hardlink":
			h.Typeflag = tar.TypeLink
			h.Mode = 0644
			h.Linkname = e.LinkName
		default:
			return nil, fmt.Errorf("unsupported entry type %q", e.Type)
		}
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
		if e.Type == "file" {
			if _, err := tw.Write([]byte(e.Data)); err != nil {
				return nil, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func SetupFixture(root string, spec CaseSpec) error {
	for _, name := range []string{"input", "destination", "protected", "scratch", "control"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(root, "protected", "sentinel.txt"), []byte("protected sentinel\n"), 0644); err != nil {
		return err
	}
	for _, obj := range spec.InitialDest {
		if obj.Type != "file" {
			return errors.New("only file initial objects are supported")
		}
		p := filepath.Join(root, "destination", filepath.FromSlash(obj.Path))
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			return err
		}
		var data string
		if obj.Path == "already.txt" {
			data = "initial\n"
		}
		if err := os.WriteFile(p, []byte(data), 0644); err != nil {
			return err
		}
	}
	archive, err := ArchiveBytes(spec)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "input", "archive.tar"), archive, 0644); err != nil {
		return err
	}
	meta, err := jsonMarshalIndent(spec)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "scratch", "case.json"), meta, 0644); err != nil {
		return err
	}
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		mode := os.FileMode(0644)
		if d.IsDir() {
			mode = 0755
		}
		if path == root {
			return os.Chmod(path, 0777)
		}
		// Give the target access without changing the permissions declared in the
		// contract. Input stays root-owned; other objects are disposable test data.
		input := filepath.Join(root, "input")
		if path != input && !strings.HasPrefix(path, input+string(filepath.Separator)) && os.Geteuid() == 0 {
			if err := os.Chown(path, 10000, 10000); err != nil {
				return err
			}
		}
		return os.Chmod(path, mode)
	})
}

func jsonMarshalIndent(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

type ExtractOptions struct {
	SkipRegularFiles bool
	LinkPolicy       string
	OverwritePolicy  string
}

func ExtractArchive(archivePath, dest string, opt ExtractOptions) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(h.Name)
		if name == "." || filepath.IsAbs(name) || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return fmt.Errorf("unsafe archive path %q", h.Name)
		}
		target := filepath.Join(dest, name)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if opt.SkipRegularFiles {
				if _, err := io.Copy(io.Discard, tr); err != nil {
					return err
				}
				continue
			}
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			if _, err := os.Lstat(target); err == nil {
				switch opt.OverwritePolicy {
				case "preserve":
					if _, err := io.Copy(io.Discard, tr); err != nil {
						return err
					}
					continue
				case "reject":
					return fmt.Errorf("refusing to overwrite %s", name)
				}
			}
			w, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(w, tr)
			closeErr := w.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		case tar.TypeSymlink, tar.TypeLink:
			switch opt.LinkPolicy {
			case "skip":
				continue
			case "reject":
				return fmt.Errorf("link rejected by policy: %s", name)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			if h.Typeflag == tar.TypeSymlink {
				if err := os.Symlink(h.Linkname, target); err != nil {
					return err
				}
			} else {
				if err := os.Link(filepath.Join(dest, filepath.Clean(h.Linkname)), target); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unsupported tar entry type %d", h.Typeflag)
		}
	}
}
