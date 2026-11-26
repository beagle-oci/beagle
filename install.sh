#!/bin/sh
# Install beagle from GitHub Releases.
#
#   curl -fsSL https://raw.githubusercontent.com/beagle-oci/beagle/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/beagle-oci/beagle/main/install.sh | sh -s -- v0.1.0
#
# Environment variables:
#   BEAGLE_VERSION      release tag to install (default: latest)
#   BEAGLE_INSTALL_DIR  target directory (default: /usr/local/bin if writable,
#                       otherwise ~/.local/bin; use "| sudo sh" for a
#                       system-wide install)
#   BEAGLE_BASE_URL     releases base URL (default: GitHub), e.g. for mirrors
#
# The script downloads the archive for the current OS and architecture,
# verifies its SHA-256 checksum against checksums.txt and installs the binary.

set -eu

REPO="beagle-oci/beagle"
BINARY="beagle"

log() { printf '%s\n' "$*" >&2; }
fail() {
	log "beagle install: $*"
	exit 1
}
has() { command -v "$1" >/dev/null 2>&1; }

download() {
	if has curl; then
		curl -fsSL --retry 3 -o "$2" "$1"
	elif has wget; then
		wget -q -O "$2" "$1"
	else
		fail "curl or wget is required"
	fi
}

sha256() {
	if has sha256sum; then
		sha256sum "$1" | cut -d ' ' -f 1
	elif has shasum; then
		shasum -a 256 "$1" | cut -d ' ' -f 1
	else
		fail "sha256sum or shasum is required to verify the download"
	fi
}

detect_platform() {
	os=$(uname -s | tr '[:upper:]' '[:lower:]')
	case "$os" in
	linux | darwin) ;;
	*) fail "unsupported operating system: $os" ;;
	esac

	arch=$(uname -m)
	case "$arch" in
	x86_64 | amd64) arch="amd64" ;;
	aarch64 | arm64) arch="arm64" ;;
	*) fail "unsupported architecture: $arch" ;;
	esac
}

choose_install_dir() {
	if [ -n "${BEAGLE_INSTALL_DIR:-}" ]; then
		dir="$BEAGLE_INSTALL_DIR"
	elif [ -w /usr/local/bin ]; then
		dir="/usr/local/bin"
	else
		dir="$HOME/.local/bin"
	fi
	mkdir -p "$dir" || fail "cannot create $dir"
	[ -w "$dir" ] || fail "$dir is not writable (set BEAGLE_INSTALL_DIR or run with sudo)"
}

main() {
	version="${1:-${BEAGLE_VERSION:-latest}}"
	base_url="${BEAGLE_BASE_URL:-https://github.com/$REPO/releases}"

	detect_platform
	archive="${BINARY}_${os}_${arch}.tar.gz"

	if [ "$version" = "latest" ]; then
		url="$base_url/latest/download"
	else
		case "$version" in
		v*) ;;
		*) version="v$version" ;;
		esac
		url="$base_url/download/$version"
	fi

	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT INT TERM

	log "Downloading $archive ($version)"
	download "$url/$archive" "$tmp/$archive" || fail "download failed: $url/$archive"
	download "$url/checksums.txt" "$tmp/checksums.txt" || fail "download failed: $url/checksums.txt"

	expected=$(awk -v f="$archive" '$2 == f { print $1 }' "$tmp/checksums.txt")
	[ -n "$expected" ] || fail "no checksum for $archive in checksums.txt"
	actual=$(sha256 "$tmp/$archive")
	[ "$expected" = "$actual" ] || fail "checksum mismatch for $archive (expected $expected, got $actual)"

	tar -xzf "$tmp/$archive" -C "$tmp" "$BINARY" || fail "cannot extract $archive"

	choose_install_dir
	if has install; then
		install -m 0755 "$tmp/$BINARY" "$dir/$BINARY"
	else
		cp "$tmp/$BINARY" "$dir/$BINARY"
		chmod 0755 "$dir/$BINARY"
	fi

	log "Installed $("$dir/$BINARY" --version) to $dir/$BINARY"
	case ":$PATH:" in
	*":$dir:"*) ;;
	*) log "Note: $dir is not in your PATH. Add it, e.g.: export PATH=\"$dir:\$PATH\"" ;;
	esac
}

# Everything runs inside main, so a partially downloaded script does nothing.
main "$@"
