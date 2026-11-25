# beagle

**beagle** is a terminal UI for OCI registries, in the spirit of
[k9s](https://k9scli.io). It lets you browse repositories, tags and
manifests and, above all, see everything that is attached to an image:
signatures, SBOMs, attestations, scan results and VEX documents, whether
they are stored as OCI 1.1 referrers, through the referrers tag fallback or as
legacy cosign tags.

```
┌──────────────────────── referrers(demo/app:v1.0.0)[11] ─────────────────────────┐
│ ARTIFACT                                          KIND         SOURCE       AGE │
│ v1.0.0                                            index                         │
│ ├─ application/vnd.dev.sigstore.bundle.v0.3+json  signature    referrer      2m │
│ ├─ application/vnd.dev.sigstore.bundle.v0.3+json  attestation  referrer      2m │
│ ├─ application/spdx+json                          sbom         referrer      2m │
│ │  └─ application/vnd.dev.sigstore.bundle.v0.3+…  signature    referrer      2m │
│ ├─ sha256-7b22f48e1be7….sig                       signature    cosign tag       │
│ ├─ linux/amd64                                    image        platform      2m │
│ │  └─ application/vnd.cncf.notary.signature       signature    referrer      2m │
│ └─ linux/arm64                                    image        platform      2m │
│    └─ application/sarif+json                      vuln-report  referrer      2m │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Features

- Browse repositories (catalog API), tags and manifests of any OCI registry
- Image indexes with their platform manifests, image manifests with config and layers
- Referrer tree per image, recursive (e.g. the signature of an SBOM) and per platform
- Works with registries that have the referrers API, registries that only support the
  OCI 1.1 tag fallback (`sha256-<hex>`), and legacy cosign tags (`.sig`, `.att`, `.sbom`)
- Classifies artifacts: signatures (cosign/sigstore bundles, Notation), SBOMs (SPDX,
  CycloneDX), attestations (in-toto, SLSA, buildx), vulnerability reports, VEX, Helm charts
- Raw JSON view with syntax highlighting for manifests and small blobs (configs, SBOMs, …)
- Harbor support: browse projects and repositories via the Harbor API (artifact and
  pull counts, public/private, proxy cache projects), no admin rights needed
- Uses your Docker credentials (`docker login`, `oras login`, credential helpers)
- k9s-style navigation: `:` commands, `/` filter, breadcrumbs, `esc` to go back

## Install

Requires Go 1.26 or newer.

```sh
go install github.com/reichertan/beagle-cli/cmd/beagle@latest
```

Or from a checkout: `make build` puts the binary into `bin/beagle`.

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
| `--version`    | Print the version                                     |

Many registries (Docker Hub, GHCR, …) do not expose the catalog API. In that
case start beagle with a repository or use `:repo <name>`.

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
| `:q`                          | Quit                            |

## Development

```sh
make registry      # terminal 1: in-memory registry with referrers API on :5050
make seed          # terminal 2: push demo images, signatures, SBOMs, charts
make run           # start beagle against localhost:5050

make registry-noreferrers                 # registry without referrers API on :5051
make seed REGISTRY=localhost:5051
```

The dev registries use ports 5050/5051 because macOS' AirPlay Receiver
occupies port 5000 and answers every request with `403 Forbidden`.

`make test` runs the unit tests (including UI tests against an in-memory
registry), `make lint` runs `go vet` and checks formatting.

See [CLAUDE.md](CLAUDE.md) for architecture notes and conventions.

## Roadmap

- Registry contexts like kubeconfig (`:ctx`), config file with skins and aliases
- Signature verification (cosign, Notation) directly from the referrer tree
- SBOM viewer (packages, licenses) and vulnerability report summary
- Provider adapters for listing repositories where `_catalog` is unavailable
  (GHCR, ECR, ACR)
- Harbor extras: show Harbor's own accessories and scan overview, labels
- Delete / copy / tag operations behind a read-write mode
- Layer file browser
