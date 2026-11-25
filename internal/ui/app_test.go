package ui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/reichertan/beagle-cli/internal/harbor"
	"github.com/reichertan/beagle-cli/internal/oci"
	"github.com/reichertan/beagle-cli/internal/oci/ocitest"
)

// harness drives the app synchronously: it executes commands and feeds the
// resulting messages back until the app is idle. Commands that do not finish
// quickly (timers such as the flash timeout) are dropped.
type harness struct {
	t   *testing.T
	app *App
}

const cmdTimeout = 150 * time.Millisecond

func newHarness(t *testing.T, r *ocitest.Registry, opts Options) *harness {
	t.Helper()
	return newHarnessWithLogin(t, r, opts, "", "")
}

// newHarnessWithLogin is like newHarness but uses the given Harbor API
// credentials when the registry has a fake Harbor API.
func newHarnessWithLogin(t *testing.T, r *ocitest.Registry, opts Options, user, pass string) *harness {
	t.Helper()
	if os.Getenv("BEAGLE_SNAPSHOT_DIR") != "" {
		lipgloss.SetColorProfile(termenv.ANSI256)
	}
	host := r.Start(t)
	client, err := oci.New(host, oci.Options{
		PlainHTTP:  true,
		Credential: func(context.Context, string) (auth.Credential, error) { return auth.EmptyCredential, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	opts.Client = client
	opts.Version = "test"
	if r.Harbor != nil {
		cred := func(context.Context) (string, string, error) { return user, pass, nil }
		hc, err := harbor.Detect(context.Background(), client.BaseURL(), client.HTTPClient(), cred)
		if err != nil {
			t.Fatal(err)
		}
		opts.Harbor = hc
	}
	h := &harness{t: t, app: New(opts)}
	h.send(tea.WindowSizeMsg{Width: 160, Height: 45})
	h.process(h.app.Init())
	return h
}

func (h *harness) send(msg tea.Msg) {
	h.t.Helper()
	_, cmd := h.app.Update(msg)
	h.process(cmd)
}

func (h *harness) process(cmd tea.Cmd) {
	h.t.Helper()
	queue := h.run(cmd)
	for len(queue) > 0 {
		msg := queue[0]
		queue = queue[1:]
		_, next := h.app.Update(msg)
		queue = append(queue, h.run(next)...)
	}
}

func (h *harness) run(cmd tea.Cmd) []tea.Msg {
	if cmd == nil {
		return nil
	}
	done := make(chan tea.Msg, 1)
	go func() { done <- cmd() }()
	var msg tea.Msg
	select {
	case msg = <-done:
	case <-time.After(cmdTimeout):
		return nil
	}
	switch msg := msg.(type) {
	case nil, spinner.TickMsg, clearFlashMsg:
		return nil
	case tea.BatchMsg:
		results := make([][]tea.Msg, len(msg))
		chans := make([]chan []tea.Msg, len(msg))
		for i, c := range msg {
			chans[i] = make(chan []tea.Msg, 1)
			go func() { chans[i] <- h.run(c) }()
		}
		var out []tea.Msg
		for i := range msg {
			results[i] = <-chans[i]
			out = append(out, results[i]...)
		}
		return out
	default:
		return []tea.Msg{msg}
	}
}

func (h *harness) key(keys ...string) {
	h.t.Helper()
	for _, k := range keys {
		switch k {
		case "enter":
			h.send(tea.KeyMsg{Type: tea.KeyEnter})
		case "esc":
			h.send(tea.KeyMsg{Type: tea.KeyEsc})
		case "down":
			h.send(tea.KeyMsg{Type: tea.KeyDown})
		default:
			h.send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)})
		}
	}
}

func (h *harness) typeText(s string) {
	h.t.Helper()
	for _, r := range s {
		h.send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
}

// screen returns the rendered view without ANSI sequences. Set
// BEAGLE_SNAPSHOT_DIR to also write the colored screen to disk.
func (h *harness) screen(name string) string {
	h.t.Helper()
	raw := h.app.View()
	if dir := os.Getenv("BEAGLE_SNAPSHOT_DIR"); dir != "" {
		_ = os.WriteFile(filepath.Join(dir, name+".ansi"), []byte(raw), 0o644)
	}
	return ansi.Strip(raw)
}

func (h *harness) expect(name string, want ...string) string {
	h.t.Helper()
	s := h.screen(name)
	for _, w := range want {
		if !strings.Contains(s, w) {
			h.t.Fatalf("screen %q does not contain %q:\n%s", name, w, s)
		}
	}
	return s
}

func TestNavigation(t *testing.T) {
	r := ocitest.New()
	f := ocitest.Seed(r)
	h := newHarness(t, r, Options{})

	h.expect("repos", "repositories[2]", "demo/app", "demo/chart", "<repositories>")

	h.key("enter")
	h.expect("tags", "tags(demo/app)[3]", "v1.0.0", "latest", "linux/amd64, linux/arm64", "index",
		f.CosignTag[:19]+"….sig", "cosign", "<tags>")

	h.key("a")
	h.expect("tags-hidden", "tags(demo/app)[2]")
	h.key("a")

	h.key("r")
	h.expect("referrers", "referrers(demo/app:latest)[8]",
		"application/spdx+json", "application/vnd.cncf.notary.signature",
		"cosign tag", "linux/amd64", "linux/arm64", "attestation", "sbom", "signature")

	h.key("esc", "enter")
	h.expect("manifest", "manifest(demo/app:latest)", "application/vnd.oci.image.index.v1+json",
		"linux/amd64", "linux/arm64", f.Index.Digest.String())

	h.key("enter")
	h.expect("image", "config", "layer 1", "application/vnd.oci.image.layer.v1.tar+gzip")

	h.key("enter")
	h.expect("config", "blob(config", `"architecture"`, `"amd64"`)

	h.key("esc", "y")
	h.expect("raw", "schemaVersion", "application/vnd.oci.image.config.v1+json")

	h.key("q", "q", "q")
	h.expect("back-to-tags", "tags(demo/app)")
}

func TestFilterAndCommands(t *testing.T) {
	r := ocitest.New()
	ocitest.Seed(r)
	h := newHarness(t, r, Options{Repository: "demo/app"})

	h.expect("start", "tags(demo/app)[3]", "<repositories>", "<tags>")

	h.key("/")
	h.typeText("v1")
	h.key("enter")
	h.expect("filtered", "tags(demo/app)[1] </v1>", "v1.0.0")

	h.key("esc")
	h.expect("unfiltered", "tags(demo/app)[3]")

	h.key(":")
	h.typeText("repo demo/chart")
	h.key("enter")
	h.expect("chart", "tags(demo/chart)[1]", "0.1.0", "helm-chart", "application/vnd.cncf.helm.config.v1+json")

	h.key(":")
	h.typeText("referrers demo/app:v1.0.0")
	h.key("enter")
	h.expect("referrers-cmd", "referrers(demo/app:v1.0.0)[8]")

	h.key(":")
	h.typeText("nope")
	h.key("enter")
	h.expect("unknown", `unknown command "nope"`)

	h.key("?")
	h.expect("help", "GENERAL", "NAVIGATION", ":repo <name>")
}

func TestCatalogUnavailable(t *testing.T) {
	r := ocitest.New()
	r.Catalog = false
	ocitest.Seed(r)
	h := newHarness(t, r, Options{})
	h.expect("no-catalog", "does not expose the catalog API", ":repo <name>")
}

func TestReferrersTagFallback(t *testing.T) {
	r := ocitest.New()
	r.ReferrersAPI = false
	ocitest.Seed(r)
	h := newHarness(t, r, Options{Repository: "demo/app", Reference: "v1.0.0"})
	h.expect("manifest", "manifest(demo/app:v1.0.0)")
	h.key("r")
	h.expect("referrers", "referrers(demo/app:v1.0.0)[8]", "application/spdx+json")
}

func TestSmallTerminal(t *testing.T) {
	r := ocitest.New()
	ocitest.Seed(r)
	h := newHarness(t, r, Options{})
	h.send(tea.WindowSizeMsg{Width: 60, Height: 15})
	s := h.screen("small")
	if lines := strings.Split(s, "\n"); len(lines) != 15 {
		t.Fatalf("expected 15 lines, got %d:\n%s", len(lines), s)
	}
	for _, l := range strings.Split(s, "\n") {
		if w := ansi.StringWidth(l); w > 60 {
			t.Fatalf("line wider than terminal (%d): %q", w, l)
		}
	}
}

func newHarborRegistry() *ocitest.Registry {
	r := ocitest.New()
	r.Catalog = false // Harbor only allows admins to use the catalog
	r.Harbor = &ocitest.HarborAPI{
		Version:    "v2.12.2-test",
		Private:    map[string]bool{"team": true},
		ProxyCache: map[string]bool{"cache": true},
		Username:   "andreas",
		Password:   "secret",
	}
	ocitest.Seed(r)
	m := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest}
	m.SchemaVersion = 2
	r.PushManifest("team/api", "1.0", ocispec.MediaTypeImageManifest, m)
	r.PushManifest("cache/library/nginx", "1.27", ocispec.MediaTypeImageManifest, m)
	return r
}

func TestHarborNavigation(t *testing.T) {
	h := newHarness(t, newHarborRegistry(), Options{})

	h.expect("projects", "projects[2]", "Harbor:", "version hidden", "cache", "proxy cache", "demo", "public", "<projects>")

	h.key("down", "enter")
	h.expect("repos", "repositories(demo)[2]", "demo/app", "demo/chart", "ARTIFACTS", "42", "<projects>", "<repositories>")

	h.key("enter")
	h.expect("tags", "tags(demo/app)[3]", "v1.0.0")

	h.key(":")
	h.typeText("projects")
	h.key("enter")
	h.expect("back", "projects[2]")

	h.key(":")
	h.typeText("project team")
	h.key("enter")
	h.expect("private", "Not allowed to list the repositories of project team", "docker login")
}

func TestHarborLogin(t *testing.T) {
	h := newHarnessWithLogin(t, newHarborRegistry(), Options{}, "andreas", "secret")
	h.expect("projects", "projects[3]", "v2.12.2-test", "team", "private")
	h.key("down", "down", "enter")
	h.expect("team", "repositories(team)[1]", "team/api")
}

func TestHarborStartWithRepository(t *testing.T) {
	h := newHarness(t, newHarborRegistry(), Options{Repository: "demo/app", Reference: "v1.0.0"})
	h.expect("start", "manifest(demo/app:v1.0.0)", "<projects>", "<repositories>", "<tags>", "<manifest>")
	h.key("esc", "esc")
	h.expect("repos", "repositories(demo)[2]")
}
