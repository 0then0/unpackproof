package up

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"
)

func TestArchiveGenerationDeterministic(t *testing.T) {
	a, err := BuildCase("nested", "allow", "replace")
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildCase("nested", "allow", "replace")
	if err != nil {
		t.Fatal(err)
	}
	if a.ArchiveSHA256 != b.ArchiveSHA256 {
		t.Fatalf("digest differs: %s != %s", a.ArchiveSHA256, b.ArchiveSHA256)
	}
	ab, err := ArchiveBytes(a)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(ab)
	if got := hex.EncodeToString(sum[:]); got != a.ArchiveSHA256 {
		t.Fatalf("stored digest %s does not match archive bytes %s", a.ArchiveSHA256, got)
	}
}

func TestTruncatedArchiveIsMalformed(t *testing.T) {
	c, err := BuildCase("truncated", "allow", "replace")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ArchiveBytes(c)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(bytes.NewReader(b))
	h, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if h.Name != "partial.txt" {
		t.Fatalf("unexpected truncated member %q", h.Name)
	}
	if _, err := io.ReadAll(tr); err == nil {
		t.Fatal("expected payload read to fail for truncated tar")
	}
}

func TestExistingPolicyExpectations(t *testing.T) {
	preserve, err := BuildCase("existing", "allow", "preserve")
	if err != nil {
		t.Fatal(err)
	}
	if preserve.Expected.Objects[0].SHA256 != file("already.txt", "initial\n").SHA256 {
		t.Fatal("preserve policy should expect initial content")
	}
	reject, err := BuildCase("existing", "allow", "reject")
	if err != nil {
		t.Fatal(err)
	}
	if reject.Expected.Exit != "nonzero" {
		t.Fatal("reject policy should expect nonzero exit")
	}
}

func TestDuplicateFollowsOverwritePolicy(t *testing.T) {
	for _, policy := range []string{"replace", "preserve", "reject"} {
		spec, err := BuildCase("duplicate", "allow", policy)
		if err != nil {
			t.Fatal(err)
		}
		want := "second\n"
		exit := "zero"
		if policy != "replace" {
			want = "first\n"
		}
		if policy == "reject" {
			exit = "nonzero"
		}
		if spec.Expected.Objects[0].SHA256 != file("dupe.txt", want).SHA256 || spec.Expected.Exit != exit {
			t.Fatalf("wrong %s contract: %#v", policy, spec.Expected)
		}
	}
	if _, err := BuildCase("links-denied", "allow", "replace"); err == nil {
		t.Fatal("incompatible link policy accepted")
	}
}
