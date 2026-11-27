package dockerhub_test

import (
	"context"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/beagle-oci/beagle/internal/dockerhub"
	"github.com/beagle-oci/beagle/internal/oci/ocitest"
)

func TestTags(t *testing.T) {
	r := ocitest.New()
	m := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest}
	m.SchemaVersion = 2
	for _, tag := range []string{"1.25", "1.26", "1.27", "latest"} {
		r.PushManifest("library/nginx", tag, ocispec.MediaTypeImageManifest, m)
	}
	pushed := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	pulled := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	hub := &ocitest.Hub{
		Registry:  r,
		PushTimes: map[string]time.Time{"library/nginx:1.27": pushed},
		PullTimes: map[string]time.Time{"library/nginx:1.27": pulled},
		PageSize:  3, // forces a second page
	}
	c := dockerhub.New(nil)
	c.BaseURL = hub.Start(t)

	// "nginx" maps to library/nginx; the 4 tags span two pages.
	infos, err := c.Tags(context.Background(), "nginx")
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 4 {
		t.Fatalf("got %d tags: %v", len(infos), infos)
	}
	if got := infos["1.27"]; !got.Pushed.Equal(pushed) || !got.Pulled.Equal(pulled) || got.Digest == "" {
		t.Fatalf("1.27 = %+v", got)
	}
	if got := infos["latest"]; !got.Pulled.IsZero() {
		t.Fatalf("latest should never have been pulled: %+v", got)
	}

	if _, err := c.Tags(context.Background(), "nobody/missing"); err == nil {
		t.Fatal("expected an error for a missing repository")
	}
}
