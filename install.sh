#!/bin/sh
# Installs the free halda tool for this machine. Needs no root and no Rust.
#   HALDA_VERSION      a release tag, such as v0.1.0. Defaults to the newest.
#   HALDA_INSTALL_DIR  where it goes. Defaults to ~/.local/bin.
#   HALDA_FROM         a folder that already holds the downloaded files.
# Stops if the file does not match its published checksum.
set -eu

repo="haldalabs/halda"
dir="${HALDA_INSTALL_DIR:-$HOME/.local/bin}"

case "$(uname -s)" in
  Darwin) os=apple-darwin ;;
  Linux) os=unknown-linux-musl ;;
  *) echo "halda: no build for $(uname -s). Build from source with cargo." >&2; exit 1 ;;
esac
case "$(uname -m)" in
  arm64 | aarch64) arch=aarch64 ;;
  x86_64 | amd64) arch=x86_64 ;;
  *) echo "halda: no build for $(uname -m). Build from source with cargo." >&2; exit 1 ;;
esac
name="halda-$arch-$os.tar.gz"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [ -n "${HALDA_FROM:-}" ]; then
  cp "$HALDA_FROM/$name" "$HALDA_FROM/SHA256SUMS" "$work/"
else
  if [ -n "${HALDA_VERSION:-}" ]; then
    base="https://github.com/$repo/releases/download/$HALDA_VERSION"
  else
    base="https://github.com/$repo/releases/latest/download"
  fi
  for file in "$name" SHA256SUMS; do
    curl -fsSL --proto '=https' --tlsv1.2 -o "$work/$file" "$base/$file" || {
      echo "halda: could not download $file from $base" >&2
      exit 1
    }
  done
fi

cd "$work"
grep " $name\$" SHA256SUMS > expected || {
  echo "halda: $name is not listed in SHA256SUMS" >&2
  exit 1
}
if command -v sha256sum > /dev/null; then
  sha256sum -c expected > /dev/null
else
  shasum -a 256 -c expected > /dev/null
fi || {
  echo "halda: checksum did not match, so nothing was installed" >&2
  exit 1
}

tar -xzf "$name"
mkdir -p "$dir"
install -m 0755 halda "$dir/halda"
echo "Installed $("$dir/halda" --version) to $dir/halda"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Add $dir to your PATH to run it by name." ;;
esac
echo "Start with: halda scan"
