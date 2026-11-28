# beagle

[![CI](https://github.com/beagle-oci/beagle/actions/workflows/ci.yml/badge.svg)](https://github.com/beagle-oci/beagle/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbeagle-oci%2Fbeagle%2Fbadges%2Fcoverage.json)](https://github.com/beagle-oci/beagle/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/beagle-oci/beagle)](https://github.com/beagle-oci/beagle/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/beagle-oci/beagle.svg)](https://pkg.go.dev/github.com/beagle-oci/beagle)
[![Go Report Card](https://goreportcard.com/badge/github.com/beagle-oci/beagle)](https://goreportcard.com/report/github.com/beagle-oci/beagle)
[![Go Version](https://img.shields.io/github/go-mod/go-version/beagle-oci/beagle)](go.mod)
[![License](https://img.shields.io/github/license/beagle-oci/beagle)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/beagle-oci/beagle/badge)](https://scorecard.dev/viewer/?uri=github.com/beagle-oci/beagle)

**beagle** is a terminal UI for OCI registries, in the spirit of
[k9s](https://k9scli.io). It lets you browse repositories, tags and
manifests and, above all, see everything that is attached to an image:
signatures, SBOMs, attestations, scan results and VEX documents, whether
they are stored as OCI 1.1 referrers, through the referrers tag fallback or as
legacy cosign tags.

```
┌────────────────────────────── referrers(demo/app:v1.0.0)[11] ───────────────────────────────┐
│ ARTIFACT                                       KIND         SOURCE      CREATED             │
│ v1.0.0                                         index                                        │
│ ├─ application/vnd.dev.sigstore.bundle.v0.3+…  signature    referrer    2026-11-27 14:02:31 │
│ ├─ application/vnd.dev.sigstore.bundle.v0.3+…  attestation  referrer    2026-11-27 14:02:31 │
│ ├─ application/spdx+json                       sbom         referrer    2026-11-27 14:02:31 │
│ │  └─ application/vnd.dev.sigstore.bundle.v0…  signature    referrer    2026-11-27 14:02:31 │
│ ├─ sha256-7b22f48e1be7….sig                    signature    cosign tag                      │
│ ├─ linux/amd64                                 image        platform    2026-11-27 14:02:31 │
│ │  └─ application/vnd.cncf.notary.signature    signature    referrer    2026-11-27 14:02:31 │
│ └─ linux/arm64                                 image        platform    2026-11-27 14:02:31 │
│    └─ application/sarif+json                   vuln-report  referrer    2026-11-27 14:02:31 │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Features

- Browse repositories (catalog API), tags and manifests of any OCI registry
- Image indexes with their platform manifests, image manifests with config and layers
- Referrer tree per image, recursive (e.g. the signature of an SBOM) and per platform
- Works with registries that have the referrers API, registries that only support the
  OCI 1.1 tag fallback (`sha256-<hex>`), and legacy cosign tags (`.sig`, `.att`, `.sbom`)
- Classifies artifacts: signatures (cosign/sigstore bundles, Notation), SBOMs (SPDX,
  CycloneDX), attestations (in-toto, SLSA, buildx), vulnerability reports, VEX, Helm charts
- Tag list with supply chain columns on every registry: **SIGNED** (cosign, Notation),
  **ATTACHED** (SBOM, attestation, VEX, scan reports) and the build time (**CREATED**)
- Verifies cosign signatures (keyless, Sigstore bundles and legacy `.sig` tags) with
  [sigstore-go](https://github.com/sigstore/sigstore-go) and shows who signed and when
- Push and pull times (**PUSHED**, **PULLED**) where the registry offers them: Harbor and
  Docker Hub; Harbor additionally shows the vulnerability scan summary (**VULNS**)
- Details are loaded only for the tags you look at, so large repositories stay fast
- Raw JSON view with syntax highlighting for manifests and small blobs (configs, SBOMs, …)
- Harbor support: browse projects and repositories via the Harbor API (artifact and
  pull counts, public/private, proxy cache projects), no admin rights needed
- Uses your Docker credentials (`docker login`, `oras login`, credential helpers)
- k9s-style navigation: `:` commands, `/` filter, breadcrumbs, `esc` to go back

## Install

On Linux and macOS (amd64 and arm64):

```sh
curl -fsSL https://raw.githubusercontent.com/beagle-oci/beagle/main/install.sh | sh
```

The script downloads the latest release for your platform, verifies its
SHA-256 checksum and installs `beagle` to `/usr/local/bin` (if writable) or
`~/.local/bin`. Options:

```sh
curl -fsSL .../install.sh | sh -s -- v0.1.0                 # specific version
curl -fsSL .../install.sh | sudo sh                          # system-wide
curl -fsSL .../install.sh | BEAGLE_INSTALL_DIR=~/bin sh      # custom directory
```

Prefer to read the script first? Download it, inspect it, then run `sh install.sh`.
If [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) is
installed, the script also verifies the release signature;
`BEAGLE_REQUIRE_SIGNATURE=1` makes that mandatory.
Archives and checksums are also available on the
[releases page](https://github.com/beagle-oci/beagle/releases).

With Go 1.27 or newer you can also build from source:

```sh
go install github.com/beagle-oci/beagle/cmd/beagle@latest
```

Or from a checkout: `make build` puts the binary into `bin/beagle`.

### Verifying releases

Every release since v0.2.0 is signed and comes with SBOMs:

- `checksums.txt` lists the SHA-256 of all archives and SBOMs and is signed
  keyless with cosign by the release workflow (`checksums.txt.sigstore.json`)
- `beagle_<os>_<arch>.tar.gz.sbom.json` is an SPDX SBOM per archive
- SLSA build provenance is stored as a GitHub attestation

```sh
# 1. Signature of the checksums (identity = this repo's release workflow)
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/beagle-oci/beagle/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# 2. The archive matches the signed checksums
sha256sum --ignore-missing -c checksums.txt

# 3. Build provenance (GitHub CLI)
gh attestation verify beagle_linux_amd64.tar.gz --repo beagle-oci/beagle
```

## Usage

```sh
beagle <registry>[/<repository>[:<tag>|@<digest>]]

beagle ghcr.io/oras-project/oras          # start in the tag list of a repository
beagle harbor.example.com                 # Harbor: start in the project list
beagle localhost:5050/demo/app:v1.0.0     # open a manifest directly
```

| Flag           | Description                                           |
| -------------- | ----------------------------------------------------- |
| `--plain-http` | Use HTTP instead of HTTPS (default for `localhost`)   |
| `--https`      | Force HTTPS, even for `localhost`                     |
| `--insecure`   | Skip TLS certificate verification                     |
| `--no-harbor`  | Do not use the Harbor API, even on Harbor             |
| `--no-verify`  | Do not verify cosign signatures                       |
| `--sigstore-root <file>` | Verify against this `trusted_root.json` instead of the Sigstore public-good instance |
| `--version`    | Print the version                                     |

Many registries (Docker Hub, GHCR, …) do not expose the catalog API. In that
case start beagle with a repository or use `:repo <name>`.

### Tag columns

| Column     | Source                                                        | Registries |
| ---------- | ------------------------------------------------------------- | ---------- |
| `SIGNED`   | Referrers (API or tag fallback), cosign `.sig` tags, Harbor accessories | all |
| `ATTACHED` | Referrers and cosign `.att`/`.sbom` tags                      | all        |
| `CREATED`  | `org.opencontainers.image.created` or the image config        | all without push times |
| `PUSHED`, `PULLED` | Vendor API                                            | Harbor, Docker Hub |
| `VULNS`    | Harbor scan overview, e.g. `C1 H3` (critical/high/...)        | Harbor     |

Times are shown in local time, to the second (`2026-11-27 14:02:31`). Press
`t` or use `:time age` to show ages (`5m`, `3d`) instead.

### Signature verification

beagle verifies cosign signatures the way `cosign verify` does for keyless
signing: the Fulcio certificate chain, the certificate transparency proof, the
transparency log entry (or a timestamp authority) and the signature over the
image digest. It handles Sigstore bundles as written by cosign v3 (OCI 1.1
referrers, or the tag fallback) and the older `sha256-<hex>.sig` tags.

| `SIGNED` | Meaning |
| -------- | ------- |
| `✓ cosign` | At least one signature is valid |
| `✗ cosign` | Signatures are attached, but none is valid |
| `? notation` | Attached, but cannot be verified: Notation (not supported yet), signed with a key, or the trusted root or registry was unavailable |
| `… cosign` | Being verified |
| `• cosign` | Attached, not verified (`--no-verify`, or on Docker Hub until you open the manifest) |

A valid signature proves that the holder of an identity signed the image, not
that you should trust that identity. The manifest view of an image shows who
signed it (email or CI workflow, OIDC issuer, source repository and commit)
and when it was logged; the referrer tree has a `VERIFIED` column for every
signature and signed attestation.

The trust root of the Sigstore public-good instance is fetched via TUF on
first use and cached in `~/.sigstore/root`, shared with cosign. For a private
Sigstore instance or offline use pass its `trusted_root.json` with
`--sigstore-root`. On Docker Hub the tag list does not verify on its own,
because fetching signature manifests counts against the pull rate limit;
opening a manifest verifies its signatures.

### Harbor

beagle detects Harbor automatically and starts in a project list instead of
the catalog (which Harbor only allows for system administrators). Projects
lead to their repositories with artifact and pull counts. Anonymous users see
public projects; run `docker login <harbor>` (user, robot account or OIDC CLI
secret) to see private ones. Harbor only reveals its version to logged-in
users, so the header may show "version hidden".

### Keys

| Key              | Action                                              |
| ---------------- | --------------------------------------------------- |
| `enter`          | Open the selected item                              |
| `r`              | Referrer tree of the selected tag / manifest        |
| `y`              | Raw manifest JSON                                   |
| `s`              | Go to the subject of a referrer                     |
| `c`              | Copy the reference to the clipboard (OSC 52)        |
| `a`              | Show/hide `sha256-*` tags in the tag list           |
| `o`              | Sort tags: registry order / newest first / name     |
| `t`              | Show times as timestamps / age                      |
| `←` `→` / `h` `l` | Scroll columns sideways when they do not fit       |
| `/`              | Filter the current list                             |
| `:`              | Command mode (`tab` completes)                      |
| `esc` / `q`      | Back (clears an active filter first)                |
| `ctrl-r`         | Reload                                              |
| `?`              | Help                                                |
| `ctrl-c`         | Quit                                                |

### Commands

| Command                       | Action                          |
| ----------------------------- | ------------------------------- |
| `:repos`                      | Back to the start view          |
| `:projects`                   | Harbor projects                 |
| `:project <name>`             | Repositories of a Harbor project |
| `:repo <name>`                | Open a repository               |
| `:open <repo:tag\|repo@digest>` | Open a manifest              |
| `:referrers <ref>`            | Referrer tree of a manifest     |
| `:time [age\|timestamp]`      | Switch the time format (toggles without argument) |
| `:q`                          | Quit                            |

## Development

```sh
make registry      # terminal 1: in-memory registry with referrers API on :5050
make seed          # terminal 2: push demo images, signatures, SBOMs, charts
make run-demo      # open demo/app on localhost:5050, trusting the demo signatures
make run           # start beagle against localhost:5050 (public-good trust root)

make registry-noreferrers                 # registry without referrers API on :5051
make seed REGISTRY=localhost:5051
```

The dev registry (olareg) has no catalog API, so `make run` opens on a hint
screen: use `:repo demo/app` (or `demo/chart`, `demo/docs`) to get going.

The demo signatures come from a virtual Sigstore instance; `make seed` writes
its trust root to `bin/demo-trusted-root.json`. `v0.9.0` carries a signature
from another instance and shows up as invalid.

The dev registries use ports 5050/5051 because macOS' AirPlay Receiver
occupies port 5000 and answers every request with `403 Forbidden`.

`make test` runs the unit tests (including UI tests against an in-memory
registry), `make cover` prints the coverage per package, `make lint` runs
`go vet` and checks formatting.

See [CLAUDE.md](CLAUDE.md) for architecture notes and conventions.

## Roadmap

1. Signature verification: cosign keyless is done; next are key-based cosign
   signatures (`--key`), Notation (trust policy and store) and identity
   policies (trusted signers per repository)
2. SBOM viewer (packages, licenses), attestation viewer (SLSA provenance) and a
   vulnerability report summary
3. Config file with registry contexts like kubeconfig (`:ctx`), per-registry
   settings, skins and aliases
4. Compare two tags (layers, config, platforms, signatures)
5. Helm chart view (`Chart.yaml`, `values.yaml`, dependencies)
6. Copy ready-to-use commands (`docker pull`, `helm pull oci://…`,
   `cosign verify`, `oras discover`)
7. Repository listing where `_catalog` is unavailable and more metadata
   providers (GHCR, ECR, ACR, Quay, GitLab), Harbor labels
8. Layer file browser
9. Script mode without the TUI, e.g. `beagle ls <repo> -o json`
10. Delete / copy / tag operations behind an explicit read-write mode

## License

beagle is licensed under the [Apache License 2.0](LICENSE).
