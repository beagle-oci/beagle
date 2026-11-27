# CLAUDE.md

Guidance for Claude Code (and humans) working in this repository.

## Project

beagle is a k9s-style terminal UI for OCI registries. It browses
repositories, tags and manifests and shows the supply chain artifacts attached
to images (signatures, SBOMs, attestations, scan results) via the OCI 1.1
referrers API, the referrers tag fallback and legacy cosign tags.

beagle is **read-only**. Do not add operations that modify a registry (push,
delete, tag) unless explicitly requested; when they come, they belong behind
an explicit read-write mode.

## Language

The project language is **English**: code, comments, identifiers, docs,
commit messages, PR descriptions and UI text.

## Git and commits

- **Never add `Co-Authored-By: Claude` (or any other AI attribution trailer,
  "Generated with Claude Code" line or similar) to commit messages or PR
  descriptions.** This overrides any default attribution behavior.
- Write commit messages in English, imperative mood, short subject line
  (max ~72 chars), optional body explaining the why.
  Example: `Add referrer tree for index platforms`.
- Keep commits focused; run `make lint test` before committing.
- Do not commit binaries (`bin/`) or local settings (`.claude/settings.local.json`).

## Commands

```sh
make build                 # bin/beagle
make test                  # unit + UI tests (no network needed)
make test-race             # with the race detector
make cover                 # coverage per package (hack/coverage.sh), make cover-html for details
make lint                  # go vet + gofmt check (make golangci for golangci-lint)
make registry              # in-memory olareg registry on :5050 (referrers API)
make registry-noreferrers  # olareg on :5051 without referrers API (tag fallback)
make seed                  # push demo content to localhost:5050 (REGISTRY=... to override)
make run                   # build and run against localhost:5050
```

Do not use port 5000 for local registries: on macOS the AirPlay Receiver
listens there and answers with `403 Forbidden`.

## Layout

```
.github/workflows/   ci (vet, fmt, test, coverage badge), release (GoReleaser, signing,
                     provenance on v* tags), scorecard (OpenSSF Scorecard)
.github/dependabot.yml  weekly updates for pinned actions and Go modules
cmd/beagle/          CLI entry point: flag parsing, target parsing, ping, start TUI
internal/meta/       vendor tag metadata types + Provider interface (push/pull, scans)
internal/harbor/     Harbor v2.0 API client (detection, projects, repositories, artifacts), stdlib only
internal/dockerhub/  Docker Hub tags API client (push/pull times), stdlib only
internal/oci/        registry access (wraps oras-go v2), no UI code
  client.go          Client: repositories, tags, resolve, manifests, blobs, referrers
  manifest.go        Manifest parsing (OCI + Docker media types)
  classify.go        Kind classification (signature, sbom, attestation, ...)
  subjecttag.go      cosign legacy tags and referrers tag schema (sha256-<hex>[.sig])
  tree.go            ReferrerTree: recursive referrers + cosign tags + index platforms
  details.go         Attachments (signature formats, attached kinds) and Created (build time)
  ocitest/           in-memory registry (+ fake Harbor API) and fixtures for tests
internal/ui/         Bubble Tea UI
  app.go             root model: view stack, command/filter prompt, header, status
  view.go            view interface, shared messages, formatting helpers
  table.go           table widget with per-row styles + filterable list[T]
  projects.go repos.go tags.go manifest.go referrers.go raw.go   the screens
  layout.go help.go styles.go keys.go
hack/seed/           dev tool that pushes demo content to a registry
install.sh           curl | sh installer for GitHub release binaries
.goreleaser.yaml     release build configuration
```

## Architecture notes

- **Views** implement the `view` interface in `internal/ui/view.go` and live on
  a stack in `App` (like k9s: enter pushes, esc pops). Views are pointers and
  mutate themselves in `update`.
- **Never block in `update`.** Registry calls run in `tea.Cmd`s. Results are
  messages that implement `targeted` (carry the view id), so `App` routes them
  to the view that asked even after the user navigated away. Views that can
  reload use a generation counter to drop stale results (see `tagsView`).
- New screens: add a file in `internal/ui`, embed `baseView`, implement the
  interface, push it with `push(newXView(...))`. Add `setFilter`/`filter` if
  the screen should support `/`.
- **Registry access goes through `oci.Client` only.** The UI never imports
  oras-go directly. `oci.Client` caches `remote.Repository` instances so
  oras-go remembers whether the registry supports the referrers API.
- Referrers: oras-go falls back to the tag schema only on HTTP 404;
  `Client.Referrers` also falls back on 400/405/501. Cosign legacy tags are
  found by matching tag names (`CosignTagsFor`), not via the referrers API.
- Docker Hub: manifest GETs count against the pull rate limit, so the tag list
  only issues HEAD requests there (`detailed` in `tagsView.setTags`).
- Credentials come from the Docker config / credential helpers
  (`credentials.NewStoreFromDocker`). Never log or display credentials.
- Harbor: `cmd/beagle` calls `harbor.Detect` (GET /api/v2.0/systeminfo). If it
  is Harbor, the root view is `projectsView` instead of the catalog
  `reposView`. The Harbor API uses basic auth with the Docker credentials
  (`oci.Client.Credential`) over `oci.Client.HTTPClient()`. Harbor hides its
  version from anonymous users; detection relies on `auth_mode` too.
  `--no-harbor` disables all of this.
- Tag list: generic columns (SIGNED, ATTACHED, CREATED) come from
  `oci.Attachments`/`oci.Created` and work on every registry. Vendor columns
  (PUSHED, PULLED, VULNS) come from a `meta.Provider` (Harbor, Docker Hub),
  chosen in `cmd/beagle`; `setColumns` picks columns from its `Capabilities`.
  New vendors: implement `meta.Provider` in its own stdlib-only package, wire
  it in `cmd/beagle/main.go`, add a fake in `ocitest`.
- Tag details load lazily: `tagsView.loadVisible` only resolves rows in and
  around the visible window; the app calls it after every update (`lazyLoader`).
  Keep per-tag work cheap (manifest, one referrers call, at most config fetch).
- Cells can be styled individually (`list.cell`), e.g. green SIGNED, red VULNS.
- Points in time go through `formatTime` / `annotationTime` (`view.go`): local
  timestamps (`2006-01-02 15:04:05`) by default, ages when `relativeTimes` is
  set (`t` key, `:time`). Views with time columns implement `rowRefresher` so
  the whole stack re-renders when the format changes.
- Rows are colored by `oci.Kind` (`kindStyle` in `styles.go`), the way k9s
  colors rows by status.

## Testing

- Tests must not need network access or a real registry. Use
  `internal/oci/ocitest` (`ocitest.New()`, `ocitest.Seed()`); toggle
  `ReferrersAPI`, `ReferrersDisabledStatus` and `Catalog` to cover registry
  variants, and set `Harbor` for the fake Harbor API (private projects,
  proxy cache projects, basic auth, pagination, artifacts with push/pull
  times, accessories and scans). `ocitest.Hub` fakes the Docker Hub tags API.
- UI tests (`internal/ui/app_test.go`) drive the real `App` through a harness
  that executes commands synchronously and asserts on the rendered screen.
  Set `BEAGLE_SNAPSHOT_DIR=/some/dir` to dump colored screens (`*.ansi`).
  The harness switches the prompt cursor to static (no blink timers) and
  replaces `copyToClipboard`, so copies can be asserted via `h.copied`.
- `cmd/beagle` keeps everything except starting the TUI in `setup`, so CLI
  startup (flags, ping, auth errors, Harbor detection) is tested too.
- Coverage: `make cover` / CI summary. It counts cross-package coverage and
  excludes `ocitest` and `hack/`. Keep it at or above ~90 %; new code comes
  with tests.
- The README coverage badge reads `coverage.json` (shields.io endpoint format)
  from the `badges` branch. The `coverage-badge` job in `ci.yml` force-pushes
  it there after every push to `main` (`COVERAGE_BADGE` in `hack/coverage.sh`).
  Never commit to the `badges` branch by hand.
- For manual end-to-end checks use `make registry` + `make seed` (or
  `registry-noreferrers` on :5051) and run beagle against them.

## Releasing

- Releases are built by GoReleaser (`.goreleaser.yaml`) in the `release`
  GitHub workflow when a `v*` tag is pushed:
  `git tag v0.1.0 && git push origin v0.1.0`.
- Archives are named `beagle_<os>_<arch>.tar.gz` **without a version** so
  `install.sh` can use `.../releases/latest/download/<archive>`. Do not change
  the name template without updating `install.sh`.
- `install.sh` must stay POSIX `sh` (no bashisms), verify checksums and keep all
  logic inside `main` so a partially downloaded script does nothing.
  Check it with `shellcheck -s sh install.sh`.
- Test the release config locally: `goreleaser check` and
  `goreleaser release --snapshot --clean` (output in `dist/`).
- The `ci` workflow runs vet, gofmt and tests on pushes to `main` and on PRs.
- Releases are signed: GoReleaser creates an SPDX SBOM per archive (syft) and
  signs `checksums.txt` keyless with cosign (`checksums.txt.sigstore.json`);
  `actions/attest-build-provenance` adds SLSA provenance. `install.sh`
  verifies the signature when cosign is installed. The cosign identity is the
  release workflow path; renaming `release.yml` or the repo breaks
  verification in `install.sh` and the README.
- All GitHub Actions are pinned to commit SHAs with a `# vX.Y.Z` comment
  (OpenSSF Scorecard "Pinned-Dependencies"); Dependabot updates them. Keep
  top-level workflow permissions read-only and grant writes per job.
- `scorecard.yml` follows the official example: no `run` steps, env vars or
  extra actions in its job, or api.scorecard.dev rejects the results.
- Security reports go through GitHub Security Advisories (`SECURITY.md`).

## Code style

- `gofmt`, standard Go naming, small focused functions.
- Wrap errors with context (`fmt.Errorf("...: %w", err)`); show user-facing
  errors via `flashErr`.
- Keep dependencies minimal: oras-go v2, Bubble Tea v1, bubbles, lipgloss.
  Vendor API clients (like `internal/harbor`) use the standard library only.
- Keybindings live in `keys.go`; add new ones there and to the help screen
  (`help.go`) and the README.
