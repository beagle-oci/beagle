package harbor_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/beagle-oci/beagle/internal/harbor"
	"github.com/beagle-oci/beagle/internal/oci/ocitest"
)

func newHarbor(t *testing.T) (*ocitest.Registry, string) {
	t.Helper()
	r := ocitest.New()
	r.Catalog = false
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
	return r, "http://" + r.Start(t)
}

func creds(user, pass string) harbor.CredentialFunc {
	return func(context.Context) (string, string, error) { return user, pass, nil }
}

func TestDetect(t *testing.T) {
	_, url := newHarbor(t)
	anon, err := harbor.Detect(context.Background(), url, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if anon.Version() != "" {
		t.Fatalf("anonymous users should not see the version, got %q", anon.Version())
	}

	authed, err := harbor.Detect(context.Background(), url, nil, creds("andreas", "secret"))
	if err != nil {
		t.Fatal(err)
	}
	if authed.Version() != "v2.12.2-test" {
		t.Fatalf("version = %q", authed.Version())
	}

	// Rejected credentials still detect Harbor (anonymously).
	if _, err := harbor.Detect(context.Background(), url, nil, creds("andreas", "nope")); err != nil {
		t.Fatalf("detection with wrong credentials failed: %v", err)
	}

	plain := ocitest.New()
	if _, err := harbor.Detect(context.Background(), "http://"+plain.Start(t), nil, nil); !errors.Is(err, harbor.ErrNotHarbor) {
		t.Fatalf("expected ErrNotHarbor, got %v", err)
	}
}

func TestProjects(t *testing.T) {
	_, url := newHarbor(t)
	ctx := context.Background()

	anon, err := harbor.Detect(ctx, url, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	anon.PageSize = 1 // force pagination
	projects, err := anon.Projects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := projectNames(projects); got != "cache,demo" {
		t.Fatalf("anonymous projects = %s", got)
	}
	if !projects[0].ProxyCache() || projects[1].ProxyCache() || !projects[1].Public() {
		t.Fatalf("unexpected project flags: %+v", projects)
	}

	authed, err := harbor.Detect(ctx, url, nil, creds("andreas", "secret"))
	if err != nil {
		t.Fatal(err)
	}
	authed.PageSize = 2
	projects, err = authed.Projects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := projectNames(projects); got != "cache,demo,team" {
		t.Fatalf("authenticated projects = %s", got)
	}
	if projects[2].Public() {
		t.Fatal("team should be private")
	}

	wrong, err := harbor.Detect(ctx, url, nil, creds("andreas", "nope"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Projects(ctx); !errors.Is(err, harbor.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestRepositories(t *testing.T) {
	_, url := newHarbor(t)
	ctx := context.Background()
	c, err := harbor.Detect(ctx, url, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	repos, err := c.Repositories(ctx, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 2 || repos[0].Name != "demo/app" || repos[0].ArtifactCount != 3 || repos[0].PullCount != 42 {
		t.Fatalf("repositories = %+v", repos)
	}

	nested, err := c.Repositories(ctx, "cache")
	if err != nil {
		t.Fatal(err)
	}
	if len(nested) != 1 || nested[0].Name != "cache/library/nginx" {
		t.Fatalf("nested repositories = %+v", nested)
	}

	if _, err := c.Repositories(ctx, "team"); !errors.Is(err, harbor.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for private project, got %v", err)
	}
	if _, err := c.Repositories(ctx, "missing"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found error, got %v", err)
	}
}

func projectNames(ps []harbor.Project) string {
	names := make([]string, len(ps))
	for i, p := range ps {
		names[i] = p.Name
	}
	return strings.Join(names, ",")
}

func TestTagMetadata(t *testing.T) {
	r, url := newHarbor(t)
	pushed := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	pulled := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	r.Harbor.PushTimes = map[string]time.Time{"demo/app:v1.0.0": pushed}
	r.Harbor.PullTimes = map[string]time.Time{"demo/app:v1.0.0": pulled}
	r.Harbor.Vulns = map[string]map[string]int{"demo/app": {"Critical": 1, "High": 2}}

	c, err := harbor.Detect(context.Background(), url, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.PageSize = 1 // the artifacts list is paginated as well
	infos, err := c.Tags(context.Background(), "demo/app")
	if err != nil {
		t.Fatal(err)
	}
	v1 := infos["v1.0.0"]
	if !v1.Pushed.Equal(pushed) || !v1.Pulled.Equal(pulled) {
		t.Fatalf("v1.0.0 times = %+v", v1)
	}
	if strings.Join(v1.Signatures, ",") != "cosign" || len(v1.Attached) != 1 || v1.Attached[0] != "sbom" {
		t.Fatalf("v1.0.0 accessories = %+v", v1)
	}
	if v1.Vulns == nil || v1.Vulns.String() != "C1 H2" || v1.Vulns.Scanner != "Trivy" {
		t.Fatalf("v1.0.0 vulns = %+v", v1.Vulns)
	}
	if latest := infos["latest"]; !latest.Pulled.IsZero() {
		t.Fatalf("latest should never have been pulled: %+v", latest)
	}

	// Nested repository names are encoded twice (a/b -> a%252Fb).
	nested, err := c.Tags(context.Background(), "cache/library/nginx")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := nested["1.27"]; !ok {
		t.Fatalf("nested repository tags = %v", nested)
	}
}
