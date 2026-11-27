package ui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/beagle-oci/beagle/internal/oci/ocitest"
)

func (h *harness) command(cmd string) {
	h.t.Helper()
	h.key(":")
	h.typeText(cmd)
	h.key("enter")
}

func (h *harness) filter(text string) {
	h.t.Helper()
	h.key("/")
	h.typeText(text)
	h.key("enter")
}

func TestReferrerActions(t *testing.T) {
	r := ocitest.New()
	f := ocitest.Seed(r)
	h := newHarness(t, r, Options{Repository: "demo/app", Reference: "v1.0.0"})
	h.expect("manifest", "manifest(demo/app:v1.0.0)")

	h.key("r")
	h.expect("referrers", "referrers(demo/app:v1.0.0)[8]")

	// The first child is the sigstore bundle signature of the index.
	h.key("down", "y")
	h.expect("raw", "raw(demo/app@"+f.Signature.Digest.String(), "dev.sigstore.bundle.content")
	h.key("esc", "c")
	h.expect("copy", "Copied ", "@"+f.Signature.Digest.String())
	if !strings.HasSuffix(h.copied, "/demo/app@"+f.Signature.Digest.String()) {
		t.Fatalf("copied %q", h.copied)
	}

	h.key("enter")
	h.expect("signature", "manifest(demo/app@"+f.Signature.Digest.String(), "Subject:", "press s", "Artifact type:")
	h.key("s")
	h.expect("subject", "manifest(demo/app@"+f.Index.Digest.String(), "linux/amd64", "linux/arm64")

	h.key("c")
	h.expect("copy-manifest", "Copied ", "@"+f.Index.Digest.String())

	h.filter("arm")
	h.expect("manifest-filter", "[1] </arm>")
	h.key("esc", "s")
	h.expect("no-subject", "This manifest has no subject")

	// Filtering the referrer tree updates the counter.
	h.key("esc", "esc")
	h.expect("back", "referrers(demo/app:v1.0.0)[8]")
	h.filter("spdx")
	h.expect("referrers-filter", "referrers(demo/app:v1.0.0)[1] </spdx>")
	h.key("esc", "ctrl+r")
	h.expect("reload", "referrers(demo/app:v1.0.0)[8]")
}

func TestManifestBlobs(t *testing.T) {
	r := ocitest.New()
	f := ocitest.Seed(r)
	h := newHarness(t, r, Options{})

	h.command("open demo/app@" + f.AMD64.Digest.String())
	h.expect("image", "config", "layer 1")

	h.key("down", "enter")
	h.expect("binary", "layer 1 is binary content")

	h.key("up", "enter")
	h.expect("config", "blob(config", `"amd64"`)
	h.key("c")
	h.expect("copied", "Copied blob to the clipboard")
	if !strings.Contains(h.copied, `"architecture": "amd64"`) {
		t.Fatalf("copied %q", h.copied)
	}
	h.key("G", "g", "down", "up", "ctrl+r")
	h.expect("config-reload", `"amd64"`)
}

func TestCommands(t *testing.T) {
	r := ocitest.New()
	ocitest.Seed(r)
	h := newHarness(t, r, Options{})

	h.command("demo/app")
	h.expect("bare-repo", "tags(demo/app)[3]")
	h.command("demo/app:v1.0.0")
	h.expect("bare-ref", "manifest(demo/app:v1.0.0)")

	h.command("open demo/app")
	h.expect("no-tag", `"demo/app" has no tag or digest`)
	h.command("referrers demo/app")
	h.expect("no-tag-referrers", `"demo/app" has no tag or digest`)
	h.command("repo")
	h.expect("usage", "usage: :repo <name>")
	h.command("projects")
	h.expect("not-harbor", "not a Harbor registry")
	h.command("project demo")
	h.expect("not-harbor-project", "not a Harbor registry")

	h.command("repos")
	h.expect("root", "repositories[2]", "<repositories>")
	h.filter("chart")
	h.expect("repos-filter", "repositories[1] </chart>")

	h.command("help")
	h.expect("help", "GENERAL")
	h.key("q")
	h.expect("help-closed", "repositories[1]")

	// esc cancels the prompt without running anything.
	h.key(":")
	h.typeText("quit")
	h.key("esc")
	h.expect("cancelled", "repositories[1]")
}

func TestTableNavigation(t *testing.T) {
	r := ocitest.New()
	m := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest}
	m.SchemaVersion = 2
	d := r.PushManifest("big/repo", "a-000", ocispec.MediaTypeImageManifest, m)
	for i := 1; i < 120; i++ {
		r.Tag("big/repo", fmt.Sprintf("a-%03d", i), d.Digest)
	}
	h := newHarness(t, r, Options{Repository: "big/repo"})
	tv := h.app.top().(*tagsView)
	body := tv.list.bodyHeight()

	h.key("G")
	if tv.list.cursor != 119 {
		t.Fatalf("G: cursor = %d", tv.list.cursor)
	}
	h.key("g")
	if tv.list.cursor != 0 {
		t.Fatalf("g: cursor = %d", tv.list.cursor)
	}
	h.send(tea.KeyMsg{Type: tea.KeyPgDown})
	if tv.list.cursor != body {
		t.Fatalf("pgdown: cursor = %d, want %d", tv.list.cursor, body)
	}
	h.send(tea.KeyMsg{Type: tea.KeyPgUp})
	h.key("j", "j", "k")
	if tv.list.cursor != 1 {
		t.Fatalf("j/k: cursor = %d", tv.list.cursor)
	}

	// Name sort is stable and the default order comes back.
	h.key("o", "o")
	h.expect("by-name", "Sorted by name")
	h.key("o")
	h.expect("registry-order", "Registry order")
}

func TestErrorAndEmptyStates(t *testing.T) {
	r := ocitest.New()
	ocitest.Seed(r)
	r.PushBlob("empty/repo", "application/octet-stream", []byte("x"))
	h := newHarness(t, r, Options{})

	h.command("repo nope/none")
	h.expect("missing-repo", "repository not found")
	h.command("repo empty/repo")
	h.expect("no-tags", "No tags.")
	h.command("open demo/app:nope")
	h.expect("missing-tag", "not found")
	h.command("referrers demo/app:nope")
	h.expect("missing-referrers", "not found")

	// Harbor rejects wrong credentials for the project list.
	hr := newHarnessWithLogin(t, newHarborRegistry(), Options{}, "andreas", "wrong")
	hr.expect("harbor-denied", "Harbor rejected the stored credentials")

	// A Harbor instance without any repositories has no projects.
	empty := ocitest.New()
	empty.Catalog = false
	empty.Harbor = &ocitest.HarborAPI{Version: "v2"}
	he := newHarness(t, empty, Options{})
	he.expect("no-projects", "No projects visible.")
}

func TestFormatContent(t *testing.T) {
	plain, rendered := formatContent([]byte(`{"a":[1,true,null,"x"],"b":-2.5e3,"c":false}`))
	if !strings.Contains(plain, `"a": [`) || !strings.Contains(rendered, `"b"`) {
		t.Fatalf("json: plain=%q rendered=%q", plain, rendered)
	}
	plain, _ = formatContent([]byte("hello\tworld"))
	if plain != "hello    world" {
		t.Fatalf("text: %q", plain)
	}
	plain, _ = formatContent([]byte{0xff, 0xfe, 0x00, 0x01})
	if plain != "binary content, 4 B" {
		t.Fatalf("binary: %q", plain)
	}
}

func TestFormatHelpers(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 5 << 20: "5.0 MiB", 3 << 30: "3.0 GiB"} {
		if got := humanSize(n); got != want {
			t.Errorf("humanSize(%d) = %q, want %q", n, got, want)
		}
	}
	for mt, want := range map[string]string{
		ocispec.MediaTypeImageIndex:                                 "oci index",
		ocispec.MediaTypeImageManifest:                              "oci manifest",
		"application/vnd.docker.distribution.manifest.list.v2+json": "docker list",
		"application/vnd.docker.distribution.manifest.v2+json":      "docker v2",
		"application/vnd.oci.artifact.manifest.v1+json":             "oci artifact",
		"":           "",
		"text/plain": "text/plain",
	} {
		if got := shortMediaType(mt); got != want {
			t.Errorf("shortMediaType(%q) = %q, want %q", mt, got, want)
		}
	}
	now := time.Now()
	for d, want := range map[time.Duration]string{
		30 * time.Second:     "30s",
		5 * time.Minute:      "5m",
		3 * time.Hour:        "3h",
		10 * 24 * time.Hour:  "10d",
		800 * 24 * time.Hour: "2y",
	} {
		if got := ageTime(now.Add(-d), "-"); got != want {
			t.Errorf("ageTime(-%v) = %q, want %q", d, got, want)
		}
	}
	if got := ageTime(time.Time{}, "never"); got != "never" {
		t.Errorf("zero time = %q", got)
	}
	if got := age("not a time"); got != "not a time" {
		t.Errorf("invalid time = %q", got)
	}
	if got := age(now.Add(48 * time.Hour).Format(time.RFC3339)); !strings.HasPrefix(got, "20") {
		t.Errorf("future time = %q", got)
	}
	if !isTextual("application/spdx+json") || isTextual("application/vnd.oci.image.layer.v1.tar+gzip") || isTextual("application/octet-stream") {
		t.Error("isTextual misclassifies media types")
	}
}
