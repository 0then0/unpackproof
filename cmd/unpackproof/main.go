package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/unpackproof/unpackproof/internal/up"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "unpackproof: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("missing command")
	}
	switch args[0] {
	case "run":
		fs := flag.NewFlagSet("run", flag.ContinueOnError)
		configPath := fs.String("config", "", "JSON config path")
		outDir := fs.String("out", "unpackproof-reports", "report output directory")
		guestPath := fs.String("guest", "", "path to unpackproof-guest Linux binary")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *configPath == "" {
			return errors.New("--config is required")
		}
		cfg, err := up.LoadConfig(*configPath)
		if err != nil {
			return err
		}
		if *guestPath == "" {
			guess := filepath.Join(filepath.Dir(os.Args[0]), "unpackproof-guest-linux-"+up.HostDockerArch())
			if _, statErr := os.Stat(guess); statErr == nil {
				*guestPath = guess
			} else {
				return errors.New("--guest is required when guest binary is not next to unpackproof")
			}
		}
		signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ctx, cancel := context.WithTimeout(signalContext, overallTimeout(cfg))
		defer cancel()
		return up.Run(ctx, cfg, *guestPath, *outDir, os.Stdout)
	case "cases":
		for _, c := range up.AllCases() {
			fmt.Printf("%s\t%s\n", c.ID, c.Description)
		}
		return nil
	case "schema":
		fmt.Println(up.ConfigSchemaSummary())
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func overallTimeout(cfg up.Config) time.Duration {
	perCase := cfg.Limits.Timeout.Duration
	if perCase <= 0 {
		perCase = 15 * time.Second
	}
	n := len(cfg.Cases)
	if n == 0 {
		n = len(up.AllCases())
	}
	return time.Duration(n+2) * (perCase + 20*time.Second)
}

func usage() {
	lines := []string{
		"Usage:",
		"  unpackproof run --config config.json --guest ./bin/unpackproof-guest-linux-arm64 --out reports",
		"  unpackproof cases",
		"  unpackproof schema",
	}
	fmt.Fprintln(os.Stderr, strings.Join(lines, "\n"))
}
