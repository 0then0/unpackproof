<p><img src="docs/icon.svg" width="96" height="96" alt="UnpackProof: an archive, a file tree, and a verification check"></p>

# UnpackProof

[![CI](https://img.shields.io/github/actions/workflow/status/0then0/unpackproof/ci.yml?branch=main&label=CI&style=flat)](https://github.com/0then0/unpackproof/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.27.1-00ADD8?style=flat)](https://go.dev/)
[![License](https://img.shields.io/badge/license-Apache--2.0-334155?style=flat)](LICENSE)
[![Filesystem](https://img.shields.io/badge/filesystem-Linux%20via%20Docker-0f766e?style=flat)](#contract)

UnpackProof is a small OSS CLI for regression testing TAR extraction behavior on synthetic fixtures in disposable Docker containers.

It is not a security scanner, CVE reproducer, exploit generator, archive bomb tester, or proof of extractor safety. v0.1 checks Linux filesystem results after extraction: expected names and bytes, link and overwrite policy, protected fixture preservation, bounded output, and cleanup status. The oracle is snapshot-based, so transient changes undone before the snapshot can remain unobserved.

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

In v0.1.1, a completed target that removes the required destination or protected root produces `FAIL` with `missing-destination-root` or `missing-protected-root`. The observer checks that the fixture directory is accessible before and after observation and that its device/inode identity matches the pre-execution baseline. Only `ENOENT` from the initial `Lstat` of the direct root establishes absence. Missing ancestors, unavailable or replaced mounts, traversal/read failures, invalid evidence and Docker failures remain observation/infrastructure errors. Timeout and interruption remain `UNRESOLVED`; memory-limit kills remain `INFRASTRUCTURE_ERROR`. Incomplete snapshots cannot establish a passing contract.

The report schemas remain `unpackproof.report.v1` and `unpackproof.case-report.v1`. Snapshot evidence gains additive fields: `fixture_root` records the accessible fixture's directory identity, and `root_missing: true` records established root absence with `root: null`, `objects: []`, and `complete: true`. Here `complete` means absence was completely observed, not that an empty directory was observed. A null root without explicit absence evidence is invalid observation evidence. Readers that reject unknown fields must accept the new fields; existing root/object fields keep their meaning. Fixture identity must match the baseline before absence can determine a verdict. Reports are persisted before destructive cleanup, including these failure cases.

## Cases

v0.1 includes stable synthetic cases:

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

The oracle compares declared permissions, symlink targets, hardlink identity, and the type of the destination root. Protected objects and their directory are compared with a baseline snapshot, including content, permissions, and device/inode identity.

## Build

The Go module and installation path are `github.com/0then0/unpackproof`. After the v0.1.1 tag is published, install the host CLI with:

```sh
go install github.com/0then0/unpackproof/cmd/unpackproof@v0.1.1
```

Build the Linux guest binary separately as below. The prepared v0.1.1 source fixes the old module declaration; published v0.1.0 is unchanged and its repository installation path has a module mismatch. The command above requires publication of that tag and has not been verified against a published release. Until publication, build this checkout or run the local installation smoke test described below.

```sh
go test ./...
go build -o bin/unpackproof ./cmd/unpackproof
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o bin/unpackproof-guest-linux-arm64 ./cmd/unpackproof-guest
```

Use `GOARCH=amd64` for Linux amd64 runners.

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

Case reports and a complete run checkpoint are written before cleanup is attempted. They include image identity, target version when configured, the normalized command and limits, execution disposition, and filesystem evidence. Persistence or cleanup errors make the CLI return nonzero while retaining the observed case verdict. Use a separate output directory for each concurrent run.

Ordinary GNU tar and the stock Python CLI can be tested directly, using the existing Python image without invoking its adapter:

```sh
# command: ["tar", "-xf", "{archive}", "-C", "{destination}"]
bin/unpackproof run --config configs/gnu-tar.json --guest bin/unpackproof-guest-linux-arm64 --out reports/gnu-tar
# command: ["python3", "-m", "tarfile", "-e", "{archive}", "{destination}"]
bin/unpackproof run --config configs/python-cli.json --guest bin/unpackproof-guest-linux-arm64 --out reports/python-cli
```

Both configs select the default 10-case corpus with `link_policy: allow` and `overwrite_policy: replace`. They use no policy adapters and retain all expectations. On Linux arm64, the local `unpackproof/python-tarfile:0.1` image ID and repo digest were `sha256:b75246ced3181e6e5ce9ae355251caada3436193b41b1853ad7a715b77970371`, built from the pinned Python base listed above. GNU tar reported version 1.34; Python reported 3.14.0. Both passed all 10 cases. For `truncated`, GNU tar exited 2 and Python exited 1; the case passed because the contract expects detection of an extraction error, not successful extraction. These are measured versions, not claims about the latest releases. Image IDs may differ across architectures or rebuilds; each run records its actual image identity and tool version.

If both primary report writes fail, a full checkpoint is saved in a private `unpackproof-recovery-*` directory under the OS temporary directory (`TMPDIR` when set). The human output and `recovery_report` field identify its path. The run stops after this case; cleanup proceeds only after evidence has been saved. Recovery files are retained for inspection, so copy them before temporary-directory cleanup. If recovery storage also fails, the target is stopped with a deadline and destructive cleanup is deferred. The reported run/case labels identify retained resources; the keeper still expires on its original deadline, after which tmpfs contents may be lost.

`SIGINT` and `SIGTERM` cancel execution. The target is stopped before observation, and cleanup uses a separate 10-second deadline. Resources are selected by unique run and case labels. Interrupted cases are `UNRESOLVED`; Docker or executable startup failures and memory-limit kills are `INFRASTRUCTURE_ERROR`.

Reports:

- `reports/<case>.json`
- `reports/run.json`
- human output on stdout

To list cases:

```sh
bin/unpackproof cases
```

## Example Adapters

`examples/python-tarfile/adapter.py` calls Python `tarfile.extractall()` with explicit filter behavior for link and overwrite policies.

`examples/node-tar/adapter.mjs` calls the current supported npm `tar` library pinned to `7.5.22`, with documented extraction options and a filter for explicit policy handling. It uses `sync: true` so each policy decision observes the completed previous member.

Controlled bad adapters are built into `unpackproof-guest adapter` for oracle sensitivity checks:

- `no-op`
- `reject-all`
- `skip-normal`
- `wrong-bytes`
- `overwrite-violate`
- `slow`

## Development Checks

Useful local checks:

```sh
go test ./...
go test -race ./...
go vet ./...
sh scripts/install-smoke.sh
go build -o bin/unpackproof ./cmd/unpackproof
GOOS=linux GOARCH=$(go env GOARCH) CGO_ENABLED=0 go build -o bin/unpackproof-guest-linux-$(go env GOARCH) ./cmd/unpackproof-guest
docker build -t unpackproof/python-tarfile:0.1 examples/python-tarfile
docker build -t unpackproof/node-tar:0.1 examples/node-tar
bin/unpackproof run --config configs/python-tarfile.json --guest bin/unpackproof-guest-linux-$(go env GOARCH) --out reports/python
bin/unpackproof run --config configs/node-tar.json --guest bin/unpackproof-guest-linux-$(go env GOARCH) --out reports/node
```

Expected-failure configs should fail the run and produce findings:

```sh
bin/unpackproof run --config configs/controlled-noop.json --guest bin/unpackproof-guest-linux-$(go env GOARCH) --out reports/noop
bin/unpackproof run --config configs/controlled-skip-normal.json --guest bin/unpackproof-guest-linux-$(go env GOARCH) --out reports/skip-normal
bin/unpackproof run --config configs/controlled-reject-all.json --guest bin/unpackproof-guest-linux-$(go env GOARCH) --out reports/reject-all
bin/unpackproof run --config configs/controlled-wrong-bytes.json --guest bin/unpackproof-guest-linux-$(go env GOARCH) --out reports/wrong-bytes
bin/unpackproof run --config configs/controlled-overwrite-violate.json --guest bin/unpackproof-guest-linux-$(go env GOARCH) --out reports/overwrite-violate
bin/unpackproof run --config configs/controlled-slow.json --guest bin/unpackproof-guest-linux-$(go env GOARCH) --out reports/slow
```

Docker regression tests (after building both images and binaries):

```sh
UNPACKPROOF_GUEST="$PWD/bin/unpackproof-guest-linux-$(go env GOARCH)" \
UNPACKPROOF_CLI="$PWD/bin/unpackproof" \
UNPACKPROOF_REPORT_ROOT="$PWD/reports/integration" \
go test -tags=integration ./internal/up -count=1 -timeout=8m
```

These tests cover real APIs, error-only suites, startup failures, policy combinations, permissions, protected identity, malformed evidence, bounded output and storage, interruption, timeout, persistence errors, cross-case isolation, concurrent runs, and cleanup ownership. GitHub Actions runs them on Linux amd64 and uploads reports even when assertions fail.

The integration suite also runs both direct compatibility configs, missing-root regressions with pre-cleanup evidence checks, observer errors, unavailable fixture mounts, incomplete observation, and missing roots during timeout/interruption. To run just the compatibility checks with the same environment variables:

```sh
go test -tags=integration ./internal/up -run '^TestIntegrationCompatibilityCLIs$' -count=1 -timeout=2m
```

`scripts/install-smoke.sh` verifies the module declaration, installs both commands from a separate temporary module using `replace` to this checkout, and runs the installed host CLI's `cases` and `schema` commands. It removes its own temporary directory afterward. This checks local installation/import resolution outside the checkout; it does not check publication, a Go module proxy, a remote tag, or Linux guest cross-compilation. CI runs it alongside unit/race tests and the existing Docker suite, without adding a platform matrix.

## Limitations

v0.1 intentionally does not cover ZIP/RAR/7z, Windows paths, hostile executables, concurrent filesystem races, fuzzing, archive bombs, historical vulnerable releases, or arbitrary untrusted payload generation. It validates synthetic TAR extraction behavior by final filesystem state and bounded evidence.

A `PASS` on this small corpus is not proof of full TAR conformance or extractor safety. Fixture identity checks establish availability for these final snapshots; they do not trace temporary filesystem mutations or eliminate races from concurrently running processes.
