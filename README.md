<p><img src="docs/icon.svg" width="96" height="96" alt="UnpackProof: an archive, a file tree, and a verification check"></p>

# UnpackProof

[![CI](https://img.shields.io/github/actions/workflow/status/0then0/unpackproof/ci.yml?branch=main&label=CI&style=flat)](https://github.com/0then0/unpackproof/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.27.1-00ADD8?style=flat)](https://go.dev/)
[![License](https://img.shields.io/badge/license-Apache--2.0-334155?style=flat)](LICENSE)
[![Filesystem](https://img.shields.io/badge/filesystem-Linux%20via%20Docker-0f766e?style=flat)](#contract)

UnpackProof is a small OSS CLI for regression testing TAR extraction behavior on synthetic fixtures in disposable Docker containers.

It checks the Linux filesystem after extraction: expected names and bytes, link and overwrite policy, preservation of protected fixture objects, bounded output, and cleanup status. An independent observer compares final filesystem snapshots with each case's expected result. Changes undone before the snapshot can remain unobserved.

## Contract

Each case runs in a fresh fixture inside a Docker volume:

```text
fixture/
  input/archive.tar
  destination/
  protected/sentinel.txt
  scratch/
```

The target command runs as UID 10000 with no network, no privileged mode, no Docker socket, read-only root filesystem, dropped capabilities, PID/memory/CPU limits, and bounded captured stdout/stderr. Limits must be positive; values that disable bounds are rejected. The case volume is a Docker local tmpfs volume owned by the run and removed after the report is saved.

Prepared images must not declare Docker `VOLUME` mounts; these would create storage outside the bounded fixture. Container logging is disabled; output is captured through attachment with a byte limit. The configured `storage_tmpfs` size bounds each fixture volume and `/tmp` separately.

Configuration is JSON. The `file` positive control is always included, even in rejection-only suites. Commands are argv arrays; UnpackProof replaces `{archive}`, `{destination}`, and `{scratch}` literally and does not invoke a shell.

Outcomes:

- `PASS`: prerequisites held, execution completed, and all checked filesystem conditions matched.
- `FAIL`: an observed contract violation such as missing object, wrong bytes, wrong type, link policy violation, overwrite violation, or protected change.
- `UNRESOLVED`: evidence was insufficient, including timeout or incomplete observation.
- `INFRASTRUCTURE_ERROR`: setup, Docker invocation, runtime, or observation failed.

A completed target that removes the required destination or protected root produces `FAIL` with `missing-destination-root` or `missing-protected-root`. The observer checks fixture access before and after the snapshot and compares its directory identity with the baseline recorded before execution. An absent root is a contract violation; an unavailable fixture or a failed observation is an infrastructure error. The observer establishes absence from a filesystem lookup of the root, not from target or Docker stderr. Errors while traversing or reading objects do not count as proof of absence.

Timeout and interruption produce `UNRESOLVED`; memory-limit kills produce `INFRASTRUCTURE_ERROR`. Incomplete snapshots cannot establish a passing contract.

## Cases

The corpus contains these deterministic synthetic cases:

- `file`
- `nested`
- `empty`
- `unicode`
- `pax`
- `duplicate`
- `existing`
- `symlink`
- `hardlink`
- `links-denied`
- `truncated`

All archive entries are intended for the extraction tree. Link targets in the corpus are internal to the controlled destination tree.

Overwrite policy applies both to pre-existing files and repeated archive members: `replace` keeps the last bytes, `preserve` keeps the first bytes, and `reject` keeps the first bytes and requires a nonzero exit. `links-denied` requires `skip` or `reject` and is omitted from default `allow` suites.

The observer compares declared permissions, symlink targets, hardlink identity, and the type of the destination root. Protected objects and their directory are compared with a baseline snapshot, including content, permissions, and device/inode identity.

## Build

You need Go 1.27.1 and Docker configured to run Linux containers. The [v0.1.1 release](https://github.com/0then0/unpackproof/releases/tag/v0.1.1) contains source code; build the binaries and example images using the commands below.

Install the released host CLI:

```sh
go install github.com/0then0/unpackproof/cmd/unpackproof@v0.1.1
```

The installed `unpackproof` executable is placed in `GOBIN`, or in `$(go env GOPATH)/bin` when `GOBIN` is unset. Add that directory to your `PATH`.

The guest binary runs inside Docker and must be built separately for Linux. Use the same release for the host CLI and guest. To obtain the release's source, configurations and example adapters:

```sh
git clone --branch v0.1.1 --depth 1 https://github.com/0then0/unpackproof.git
cd unpackproof
```

Build the guest for the Docker engine's architecture, which may differ from your host's architecture. For Linux arm64:

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o bin/unpackproof-guest-linux-arm64 ./cmd/unpackproof-guest
```

For Linux amd64, use `GOARCH=amd64` and name the output `bin/unpackproof-guest-linux-amd64`.

You can also build the host CLI from the same checkout:

```sh
go build -o bin/unpackproof ./cmd/unpackproof
```

The examples below run from the repository root and use this `bin/unpackproof` executable. If you installed the host CLI with `go install`, use `unpackproof` instead. Replace the guest path with the amd64 binary when using a Linux amd64 Docker engine.

Build example adapters:

```sh
docker build -t unpackproof/python-tarfile:0.1 examples/python-tarfile
docker build -t unpackproof/node-tar:0.1 examples/node-tar
```

The example images pin runtimes by digest:

- `python:3.14.0-slim-bookworm@sha256:d13fa0424035d290decef3d575cea23d1b7d5952cdf429df8f5542c71e961576`
- `node:24.21.0-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6`

The Node example pins `tar@7.5.22` in `examples/node-tar/package-lock.json`.

## Run

```sh
bin/unpackproof run \
  --config configs/python-tarfile.json \
  --guest bin/unpackproof-guest-linux-arm64 \
  --out reports/python
```

Ordinary GNU tar and the stock Python CLI can be tested directly, using the existing Python image without invoking its adapter:

```sh
# command: ["tar", "-xf", "{archive}", "-C", "{destination}"]
bin/unpackproof run --config configs/gnu-tar.json --guest bin/unpackproof-guest-linux-arm64 --out reports/gnu-tar
# command: ["python3", "-m", "tarfile", "-e", "{archive}", "{destination}"]
bin/unpackproof run --config configs/python-cli.json --guest bin/unpackproof-guest-linux-arm64 --out reports/python-cli
```

Both configs use the default 10-case corpus with `link_policy: allow` and `overwrite_policy: replace`. The [v0.1.1 release notes](https://github.com/0then0/unpackproof/releases/tag/v0.1.1) record successful runs with GNU tar 1.34 and Python 3.14.0, including the tested image identity. Each run records its actual image identity and tool version, which may differ across architectures or rebuilds.

For `truncated`, `PASS` means the extractor detected an extraction error and exited nonzero while preserving the checked filesystem contract. It does not mean the truncated archive was successfully extracted.

`SIGINT` and `SIGTERM` cancel execution. The target is stopped before observation, and cleanup uses a separate 10-second deadline. Resources are selected by unique run and case labels. Interrupted cases are `UNRESOLVED`; Docker or executable startup failures and memory-limit kills are `INFRASTRUCTURE_ERROR`.

To list the corpus or inspect the configuration fields:

```sh
bin/unpackproof cases
bin/unpackproof schema
```

## Reports and Cleanup

A run saves reports in the directory selected by `--out` (default: `unpackproof-reports`) and prints a human-readable result to stdout:

- `<out>/<case>.json`
- `<out>/run.json`

Case reports include the command, limits, image identity, target version when configured, execution disposition, findings, filesystem evidence, and cleanup status. Case reports and a run checkpoint are saved before destructive cleanup. Persistence or cleanup errors make the CLI return nonzero while retaining the observed case verdict. Use a separate output directory for each concurrent run.

The JSON schemas are `unpackproof.report.v1` for runs and `unpackproof.case-report.v1` for cases. Snapshot evidence distinguishes an observed object from an absent root:

- `root` describes the observed root; `objects` contains its observed descendants.
- `fixture_root` records the accessible fixture directory's device/inode identity.
- `root_missing: true` records proven root absence, with `root: null`, `objects: []`, and `complete: true`. Here `complete` means absence was completely observed; no empty directory was observed.
- `complete: false` and `incomplete_reason` describe an incomplete snapshot. A null root without explicit absence evidence is invalid observation evidence.

The `root_missing` and `fixture_root` fields were added in v0.1.1 without changing the schema identifiers or the meaning of existing root/object fields. Consumers that reject unknown fields must accept these additions. Update the host CLI and Linux guest together.

If neither the case report nor the run checkpoint can be written, a recovery checkpoint is saved in a private `unpackproof-recovery-*` directory under the OS temporary directory (`TMPDIR` when set). The human output and `recovery_report` field give its path. The run stops after that case. Recovery files are retained for inspection; copy them before temporary-directory cleanup.

If recovery storage also fails, UnpackProof stops the target with a deadline and defers destructive cleanup. The report identifies retained resources by run and case labels. The container keeping the tmpfs fixture mounted still expires on its original deadline, after which the contents may be lost.

## Example Adapters

`examples/python-tarfile/adapter.py` calls Python `tarfile.extractall()` with explicit filter behavior for link and overwrite policies.

`examples/node-tar/adapter.mjs` calls the npm `tar` library pinned to `7.5.22`, with extraction options and a filter for explicit policy handling. It uses `sync: true` so each policy decision observes the completed previous member.

The guest includes deliberately incorrect adapters for checking that the observer detects known violations. They can be run with the `configs/controlled-*.json` configurations:

- `no-op`
- `reject-all`
- `skip-normal`
- `wrong-bytes`
- `overwrite-violate`
- `slow`

## Development Checks

Run unit tests, the race detector, static analysis, and the local installation smoke test:

```sh
go test ./...
go test -race ./...
go vet ./...
sh scripts/install-smoke.sh
```

Build the current source and example images before running Docker tests. The integration tests also require Python 3 on the host. Set `docker_arch` to the Docker engine's architecture (`arm64` or `amd64`):

```sh
docker_arch=arm64
go build -o bin/unpackproof ./cmd/unpackproof
GOOS=linux GOARCH="$docker_arch" CGO_ENABLED=0 go build -o "bin/unpackproof-guest-linux-$docker_arch" ./cmd/unpackproof-guest
docker build -t unpackproof/python-tarfile:0.1 examples/python-tarfile
docker build -t unpackproof/node-tar:0.1 examples/node-tar
bin/unpackproof run --config configs/python-tarfile.json --guest "bin/unpackproof-guest-linux-$docker_arch" --out reports/python
bin/unpackproof run --config configs/node-tar.json --guest "bin/unpackproof-guest-linux-$docker_arch" --out reports/node
```

Expected-failure configs should fail the run and produce findings:

```sh
bin/unpackproof run --config configs/controlled-noop.json --guest "bin/unpackproof-guest-linux-$docker_arch" --out reports/noop
bin/unpackproof run --config configs/controlled-skip-normal.json --guest "bin/unpackproof-guest-linux-$docker_arch" --out reports/skip-normal
bin/unpackproof run --config configs/controlled-reject-all.json --guest "bin/unpackproof-guest-linux-$docker_arch" --out reports/reject-all
bin/unpackproof run --config configs/controlled-wrong-bytes.json --guest "bin/unpackproof-guest-linux-$docker_arch" --out reports/wrong-bytes
bin/unpackproof run --config configs/controlled-overwrite-violate.json --guest "bin/unpackproof-guest-linux-$docker_arch" --out reports/overwrite-violate
bin/unpackproof run --config configs/controlled-slow.json --guest "bin/unpackproof-guest-linux-$docker_arch" --out reports/slow
```

Docker regression tests (after building both images and binaries):

```sh
export UNPACKPROOF_GUEST="$PWD/bin/unpackproof-guest-linux-$docker_arch"
export UNPACKPROOF_CLI="$PWD/bin/unpackproof"
export UNPACKPROOF_REPORT_ROOT="$PWD/reports/integration"
go test -tags=integration ./internal/up -count=1 -timeout=8m
```

The suite covers the example adapters, direct GNU tar and Python CLI commands, policy combinations, missing roots, observer failures, incomplete observation, permissions, link and protected identity, runtime limits, interruption, timeout, report persistence, concurrent runs, isolation, and cleanup ownership. GitHub Actions runs the suite on Linux amd64 and uploads reports even when assertions fail.

To run only the direct CLI compatibility checks, keep the environment variables above set and run:

```sh
go test -tags=integration ./internal/up -run '^TestIntegrationCompatibilityCLIs$' -count=1 -timeout=2m
```

`scripts/install-smoke.sh` verifies the module declaration, installs both commands from a separate temporary module using `replace` to the checkout, and runs the installed host CLI's `cases` and `schema` commands. It removes its own temporary directory afterward. This checks local installation and import resolution outside the checkout; it does not check a published tag, a Go module proxy, or Linux guest cross-compilation. CI runs it alongside unit/race tests and the Docker suite.

## Limitations

UnpackProof validates synthetic TAR extraction behavior by final filesystem state and bounded evidence. ZIP/RAR/7z, Windows paths, hostile executables, concurrent filesystem races, fuzzing, archive bombs, historical vulnerable releases, and arbitrary untrusted payload generation are outside its scope. It is not a security scanner, CVE reproducer, or exploit generator.

A `PASS` on this small corpus is not proof of full TAR conformance or extractor safety. Fixture identity checks establish availability for these final snapshots; they do not trace temporary filesystem mutations or eliminate races from concurrently running processes.
