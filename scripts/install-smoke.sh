#!/bin/sh
set -eu

source_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
module=github.com/0then0/unpackproof
# Local replace alone tolerates mismatched module declarations. Check the
# declaration too, so this test protects the public installation namespace.
test "$(cd "$source_root" && go list -m)" = "$module"
smoke_dir=$(mktemp -d "${TMPDIR:-/tmp}/unpackproof-install-XXXXXX")
trap 'rm -rf "$smoke_dir"' EXIT HUP INT TERM
cd "$smoke_dir"
go mod init unpackproof-install-smoke
go mod edit "-require=$module@v0.0.0" "-replace=$module=$source_root"
GOBIN="$smoke_dir/bin" go install "$module/cmd/unpackproof" "$module/cmd/unpackproof-guest"
case "$("$smoke_dir/bin/unpackproof" cases)" in
  *file*truncated*) ;;
  *) echo 'installed CLI did not list the corpus' >&2; exit 1 ;;
esac
case "$("$smoke_dir/bin/unpackproof" schema)" in
  *unpackproof.config.v1*) ;;
  *) echo 'installed CLI did not expose the config schema' >&2; exit 1 ;;
esac
go version -m "$smoke_dir/bin/unpackproof" "$smoke_dir/bin/unpackproof-guest"
echo 'Installation smoke passed outside checkout using a local replace.'
echo 'This does not verify a published tag, module proxy, or Linux guest cross-build.'
