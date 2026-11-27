package ui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/beagle-oci/beagle/internal/dockerhub"
	"github.com/beagle-oci/beagle/internal/harbor"
	"github.com/beagle-oci/beagle/internal/oci"
	"github.com/beagle-oci/beagle/internal/oci/ocitest"
)

// harness drives the app synchronously: it executes commands and feeds the
// resulting messages back until the app is idle. Commands that do not finish
// quickly (timers such as the flash timeout) are dropped.
type harness struct {
	t      *testing.T
	app    *App
	copied string
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
		if opts.Metadata == nil {
			opts.Metadata = hc
		}
	}
	h := &harness{t: t, app: New(opts)}
	orig := copyToClipboard
	copyToClipboard = func(s string) { h.copied = s }
	t.Cleanup(func() { copyToClipboard = orig })
	// A blinking cursor schedules timers on every key press, which the
	// harness would have to wait out.
	h.app.input.Cursor.SetMode(cursor.CursorStatic)
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
	s := h.expect("image", "config", "layer 1", "application/vnd.oci.image.layer.v1.tar+gzip")
	if strings.Contains(s, "unknown") {
		t.Fatalf("image config and layers should have a kind:\n%s", s)
	}
	if f := strings.Fields(row(t, s, ocispec.MediaTypeImageConfig)); f[2] != "config" {
		t.Fatalf("config row kind = %q", f[2])
	}
	if f := strings.Fields(row(t, s, "layer 1")); f[3] != "layer" {
		t.Fatalf("layer row kind = %q", f[3])
	}

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
	h.expect("tags", "tags(demo/app · harbor)[3]", "v1.0.0")

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

// row returns the screen line that contains needle.
func row(t *testing.T, screen, needle string) string {
	t.Helper()
	for _, l := range strings.Split(screen, "\n") {
		if strings.Contains(l, needle) {
			return l
		}
	}
	t.Fatalf("no line contains %q:\n%s", needle, screen)
	return ""
}

func TestTagColumnsGeneric(t *testing.T) {
	r := ocitest.New()
	ocitest.Seed(r)
	h := newHarness(t, r, Options{Repository: "demo/app"})
	s := h.expect("generic", "SIGNED", "ATTACHED", "CREATED")
	if strings.Contains(s, "PUSHED") || strings.Contains(s, "VULNS") {
		t.Fatalf("generic registry should not show vendor columns:\n%s", s)
	}
	v1 := row(t, s, "v1.0.0")
	for _, want := range []string{"✓ cosign", "sbom att", formatTime(ocitest.Created, "-")} {
		if !strings.Contains(v1, want) {
			t.Fatalf("row %q lacks %q", v1, want)
		}
	}
}

func TestTagColumnsHarbor(t *testing.T) {
	r := newHarborRegistry()
	latestPushed := time.Now().Add(-72 * time.Hour)
	v1Pushed, v1Pulled := time.Now().Add(-2*time.Hour), time.Now().Add(-30*time.Minute)
	r.Harbor.PushTimes = map[string]time.Time{
		"demo/app:latest": latestPushed,
		"demo/app:v1.0.0": v1Pushed,
	}
	r.Harbor.PullTimes = map[string]time.Time{"demo/app:v1.0.0": v1Pulled}
	r.Harbor.Vulns = map[string]map[string]int{"demo/app": {"Critical": 1, "High": 2}}
	h := newHarness(t, r, Options{Repository: "demo/app"})

	s := h.expect("harbor", "tags(demo/app · harbor)[3]", "PUSHED", "PULLED", "VULNS")
	if strings.Contains(s, "CREATED") {
		t.Fatalf("Harbor shows push times instead of build times:\n%s", s)
	}
	v1 := row(t, s, "v1.0.0")
	for _, want := range []string{"✓ cosign", formatTime(v1Pushed, "-"), formatTime(v1Pulled, "-"), "C1 H2"} {
		if !strings.Contains(v1, want) {
			t.Fatalf("row %q lacks %q", v1, want)
		}
	}
	if latest := row(t, s, "latest"); !strings.Contains(latest, "never") || !strings.Contains(latest, formatTime(latestPushed, "-")) {
		t.Fatalf("latest row = %q", latest)
	}

	// Registry order lists latest first; "newest first" puts v1.0.0 on top.
	h.key("o")
	s = h.expect("sorted", "push time")
	if strings.Index(s, "v1.0.0") > strings.Index(s, " latest ") {
		t.Fatalf("v1.0.0 should come first when sorted by push time:\n%s", s)
	}
}

func TestTagColumnsDockerHub(t *testing.T) {
	r := ocitest.New()
	ocitest.Seed(r)
	pulled := time.Now().Add(-3 * time.Hour)
	hub := &ocitest.Hub{Registry: r, PullTimes: map[string]time.Time{"demo/app:v1.0.0": pulled}}
	hc := dockerhub.New(nil)
	hc.BaseURL = hub.Start(t)

	h := newHarness(t, r, Options{Repository: "demo/app", Metadata: hc})
	s := h.expect("hub", "tags(demo/app · docker-hub)[3]", "PUSHED", "PULLED")
	if strings.Contains(s, "VULNS") {
		t.Fatalf("Docker Hub provides no scan results:\n%s", s)
	}
	if v1 := row(t, s, "v1.0.0"); !strings.Contains(v1, formatTime(pulled, "-")) {
		t.Fatalf("row %q lacks the pull time", v1)
	}
}

func TestHorizontalScroll(t *testing.T) {
	r := newHarborRegistry()
	r.Harbor.Vulns = map[string]map[string]int{"demo/app": {"Critical": 1}}
	h := newHarness(t, r, Options{Repository: "demo/app"})
	h.send(tea.WindowSizeMsg{Width: 90, Height: 15})

	s := h.expect("narrow", "TAG", "KIND", "▶")
	if strings.Contains(s, "VULNS") || strings.Contains(s, "◀") {
		t.Fatalf("narrow tag list should hide the right columns:\n%s", s)
	}
	h.key("right", "l", "l", "l", "l")
	s = h.expect("scrolled", "TAG", "◀", "VULNS", "INFO", "C1")
	if strings.Contains(s, "KIND") || strings.Contains(s, "▶") {
		t.Fatalf("scrolled tag list should hide the left columns:\n%s", s)
	}
	h.key("left", "h", "h", "h", "h")
	h.expect("back", "KIND", "▶")

	// Wide enough: nothing to scroll.
	h.send(tea.WindowSizeMsg{Width: 200, Height: 15})
	if s := h.expect("wide", "KIND", "VULNS"); strings.ContainsAny(s, "◀▶") {
		t.Fatalf("wide tag list shows scroll arrows:\n%s", s)
	}
}

func TestHelpLayout(t *testing.T) {
	for _, w := range []int{200, 120, 50} {
		help := renderHelp(w, 60)
		for _, want := range []string{"GENERAL", "NAVIGATION", "RESOURCE", "COMMANDS", ":q"} {
			if !strings.Contains(help, want) {
				t.Fatalf("help at width %d lacks %q:\n%s", w, want, help)
			}
		}
		lines := strings.Split(help, "\n")
		if w == 120 && len(lines) > 30 {
			t.Fatalf("help at width 120 should use two sections per row, got %d lines", len(lines))
		}
		if w == 200 && len(lines) > 15 {
			t.Fatalf("help at width 200 should show all sections side by side, got %d lines", len(lines))
		}
	}
}

func TestTimeToggle(t *testing.T) {
	t.Cleanup(func() { relativeTimes = false })
	r := newHarborRegistry()
	pushed := time.Now().Add(-2 * time.Hour)
	r.Harbor.PushTimes = map[string]time.Time{"demo/app:v1.0.0": pushed}
	h := newHarness(t, r, Options{Repository: "demo/app"})

	stamp := pushed.Local().Format(timeLayout)
	if v1 := row(t, h.expect("timestamps", "PUSHED"), "v1.0.0"); !strings.Contains(v1, stamp) {
		t.Fatalf("row %q lacks the push timestamp %q", v1, stamp)
	}

	h.key("t")
	if v1 := row(t, h.expect("age", "Times shown as age"), "v1.0.0"); !strings.Contains(v1, "2h") || strings.Contains(v1, stamp) {
		t.Fatalf("row %q should show the age", v1)
	}

	// Views further down the stack follow the setting.
	updated := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) // ocitest Harbor update_time
	h.key("esc")
	if repo := row(t, h.expect("repos-age", "UPDATED"), "│ demo/app "); !strings.Contains(repo, age(updated)) {
		t.Fatalf("repository row %q should show the age", repo)
	}

	h.key(":")
	h.typeText("time timestamp")
	h.key("enter")
	s := h.expect("repos-timestamps", "Times shown as timestamps")
	if repo := row(t, s, "│ demo/app "); !strings.Contains(repo, updated.Local().Format(timeLayout)) {
		t.Fatalf("repository row %q should show the timestamp", repo)
	}

	for _, c := range []struct{ cmd, want string }{
		{"time", "Times shown as age"},
		{"time age", "Times shown as age"},
		{"time", "Times shown as timestamps"},
		{"time soon", "usage: :time [age|timestamp]"},
	} {
		h.key(":")
		h.typeText(c.cmd)
		h.key("enter")
		h.expect(c.cmd, c.want)
	}
	if relativeTimes {
		t.Fatal("an invalid :time argument must not change the format")
	}

	h.key("?")
	h.expect("help", "timestamps / age", ":time [age|timestamp]")
}

func TestLazyLoading(t *testing.T) {
	r := ocitest.New()
	m := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest}
	m.SchemaVersion = 2
	d := r.PushManifest("big/repo", "tag-000", ocispec.MediaTypeImageManifest, m)
	for i := 1; i < 300; i++ {
		r.Tag("big/repo", fmt.Sprintf("tag-%03d", i), d.Digest)
	}
	h := newHarness(t, r, Options{Repository: "big/repo"})
	h.expect("big", "tags(big/repo)[300]")

	tv := h.app.top().(*tagsView)
	loaded := func() int {
		n := 0
		for _, it := range tv.all {
			if it.state != stateIdle {
				n++
			}
		}
		return n
	}
	if n := loaded(); n == 0 || n > 60 {
		t.Fatalf("expected only the visible rows to load, got %d of 300", n)
	}
	h.key("G")
	if last := tv.all[299]; last.state != stateDone {
		t.Fatalf("the last tag should load after jumping to the bottom (state %d)", last.state)
	}
	if n := loaded(); n > 120 {
		t.Fatalf("jumping to the bottom should not load everything, got %d", n)
	}
}
