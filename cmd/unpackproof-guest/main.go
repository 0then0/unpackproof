package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/0then0/unpackproof/internal/up"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "unpackproof-guest: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("missing command")
	}
	switch args[0] {
	case "hold":
		fs := flag.NewFlagSet("hold", flag.ContinueOnError)
		seconds := fs.Int("seconds", 600, "seconds to keep the fixture volume mounted")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		time.Sleep(time.Duration(*seconds) * time.Second)
		return nil
	case "setup":
		fs := flag.NewFlagSet("setup", flag.ContinueOnError)
		caseID := fs.String("case", "", "case ID")
		root := fs.String("root", "/fixture", "fixture root")
		linkPolicy := fs.String("link-policy", "allow", "allow, skip, or reject")
		overwritePolicy := fs.String("overwrite-policy", "replace", "replace, preserve, or reject")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		spec, err := up.BuildCase(*caseID, *linkPolicy, *overwritePolicy)
		if err != nil {
			return err
		}
		return up.SetupFixture(*root, spec)
	case "snapshot":
		fs := flag.NewFlagSet("snapshot", flag.ContinueOnError)
		root := fs.String("root", "/fixture", "fixture root")
		subpath := fs.String("subpath", "destination", "subpath under fixture")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		snap, err := up.SnapshotFixture(*root, *subpath, up.SnapshotLimit{MaxEntries: 2048, MaxFileBytes: 8 << 20})
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(snap)
	case "probe":
		fs := flag.NewFlagSet("probe", flag.ContinueOnError)
		root := fs.String("root", "/fixture", "fixture root")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(up.Probe(filepath.Join(*root, "scratch")))
	case "adapter":
		return runControlledAdapter(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runControlledAdapter(args []string) error {
	if len(args) == 0 {
		return errors.New("missing adapter mode")
	}
	mode := args[0]
	fs := flag.NewFlagSet("adapter "+mode, flag.ContinueOnError)
	archive := fs.String("archive", "", "archive path")
	dest := fs.String("destination", "", "destination path")
	delay := fs.Duration("delay", 0, "optional delay")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *delay > 0 {
		time.Sleep(*delay)
	}
	switch mode {
	case "no-op":
		return nil
	case "reject-all":
		return errors.New("controlled reject-all adapter")
	case "slow":
		time.Sleep(30 * time.Second)
		return nil
	case "skip-normal":
		return up.ExtractArchive(*archive, *dest, up.ExtractOptions{SkipRegularFiles: true, LinkPolicy: "allow", OverwritePolicy: "replace"})
	case "wrong-bytes":
		if err := up.ExtractArchive(*archive, *dest, up.ExtractOptions{LinkPolicy: "allow", OverwritePolicy: "replace"}); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(*dest, "hello.txt"), []byte("wrong bytes\n"), 0644)
	case "overwrite-violate":
		if err := os.WriteFile(filepath.Join(*dest, "already.txt"), []byte("overwritten despite preserve\n"), 0644); err != nil {
			return err
		}
		_, err := io.Copy(io.Discard, os.Stdin)
		return err
	default:
		return fmt.Errorf("unknown controlled adapter %q", mode)
	}
}
