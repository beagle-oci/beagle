package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beagle-oci/beagle/internal/oci"
	"github.com/beagle-oci/beagle/internal/oci/ocitest"
	"github.com/beagle-oci/beagle/internal/sigverify/sigtest"
	"github.com/beagle-oci/beagle/internal/ui"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		in, host, repo, ref string
	}{
		{"localhost:5000", "localhost:5000", "", ""},
		{"https://ghcr.io/", "ghcr.io", "", ""},
		{"ghcr.io/oras-project/oras", "ghcr.io", "oras-project/oras", ""},
		{"ghcr.io/oras-project/oras:v1.2.0", "ghcr.io", "oras-project/oras", "v1.2.0"},
		{"localhost:5000/demo/app@sha256:abc", "localhost:5000", "demo/app", "sha256:abc"},
		{"docker.io/library/nginx:1.27", "docker.io", "library/nginx", "1.27"},
	}
	for _, tt := range tests {
		host, repo, ref := parseTarget(tt.in)
		if host != tt.host || repo != tt.repo || ref != tt.ref {
			t.Errorf("parseTarget(%q) = %q, %q, %q; want %q, %q, %q", tt.in, host, repo, ref, tt.host, tt.repo, tt.ref)
		}
	}
}

// isolate keeps tests away from the developer's Docker credentials.
func isolate(t *testing.T) {
	t.Helper()
	t.Setenv("DOCKER_CONFIG", t.TempDir())
}

func runSetup(t *testing.T, args ...string) (ui.Options, string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	opts, err := setup(args, &stdout, &stderr)
	return opts, stdout.String(), stderr.String(), err
}

func TestSetupVersionAndHelp(t *testing.T) {
	isolate(t)
	_, out, _, err := runSetup(t, "--version")
	if !errors.Is(err, errDone) || !strings.Contains(out, "beagle dev") {
		t.Fatalf("--version: err=%v out=%q", err, out)
	}
	_, _, errOut, err := runSetup(t, "-h")
	if !errors.Is(err, errDone) || !strings.Contains(errOut, "Usage:") || !strings.Contains(errOut, "-no-harbor") {
		t.Fatalf("-h: err=%v stderr=%q", err, errOut)
	}
	if _, _, _, err := runSetup(t, "--bogus"); err == nil {
		t.Fatal("unknown flags must fail")
	}
	if _, _, errOut, err := runSetup(t); err == nil || !strings.Contains(errOut, "Usage:") {
		t.Fatalf("missing argument: err=%v", err)
	}
}

func TestSetupGenericRegistry(t *testing.T) {
	isolate(t)
	r := ocitest.New()
	ocitest.Seed(r)
	host := r.Start(t)

	opts, _, _, err := runSetup(t, host+"/demo/app:v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if opts.Repository != "demo/app" || opts.Reference != "v1.0.0" {
		t.Fatalf("target = %q %q", opts.Repository, opts.Reference)
	}
	if !opts.Client.PlainHTTP() {
		t.Fatal("localhost registries should default to plain HTTP")
	}
	if opts.Harbor != nil || opts.Metadata != nil {
		t.Fatalf("a plain registry has no vendor API: %+v", opts)
	}
}

func TestSetupHarbor(t *testing.T) {
	isolate(t)
	r := ocitest.New()
	r.Harbor = &ocitest.HarborAPI{Version: "v2.12.2"}
	ocitest.Seed(r)
	host := r.Start(t)

	opts, _, _, err := runSetup(t, host)
	if err != nil {
		t.Fatal(err)
	}
	if opts.Harbor == nil || opts.Metadata == nil || opts.Metadata.Name() != "harbor" {
		t.Fatalf("Harbor not detected: %+v", opts)
	}

	opts, _, _, err = runSetup(t, "--no-harbor", host)
	if err != nil {
		t.Fatal(err)
	}
	if opts.Harbor != nil || opts.Metadata != nil {
		t.Fatalf("--no-harbor should disable the Harbor API: %+v", opts)
	}
}

func TestSetupErrors(t *testing.T) {
	isolate(t)
	r := ocitest.New()
	r.Username, r.Password = "andreas", "secret"
	host := r.Start(t)

	_, _, _, err := runSetup(t, host)
	if err == nil || !strings.Contains(err.Error(), "requires authentication") || !strings.Contains(err.Error(), "docker login "+host) {
		t.Fatalf("expected an authentication hint, got %v", err)
	}

	// --https against a plain HTTP server fails the TLS handshake.
	open := ocitest.New().Start(t)
	if _, _, _, err := runSetup(t, "--https", open); err == nil || !strings.Contains(err.Error(), "cannot reach registry") {
		t.Fatalf("expected a connection error with --https, got %v", err)
	}

	if _, _, _, err := runSetup(t, "Not A Host"); err == nil {
		t.Fatal("invalid registry names must fail")
	}
}

func TestSelectProvider(t *testing.T) {
	isolate(t)
	hub, err := oci.New("docker.io", oci.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if p := selectProvider(hub, nil); p == nil || p.Name() != "docker-hub" {
		t.Fatalf("docker.io should use the Docker Hub API, got %v", p)
	}
	other, err := oci.New("ghcr.io", oci.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if p := selectProvider(other, nil); p != nil {
		t.Fatalf("ghcr.io has no provider yet, got %s", p.Name())
	}
}

func TestSetupWithCredentials(t *testing.T) {
	r := ocitest.New()
	r.Username, r.Password = "andreas", "secret"
	ocitest.Seed(r)
	host := r.Start(t)

	// A Docker config with credentials for the registry, like docker login.
	dir := t.TempDir()
	auth := base64.StdEncoding.EncodeToString([]byte("andreas:secret"))
	cfg := fmt.Sprintf(`{"auths":{%q:{"auth":%q}}}`, host, auth)
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_CONFIG", dir)

	opts, _, _, err := runSetup(t, host+"/demo/app")
	if err != nil {
		t.Fatalf("stored credentials should be used: %v", err)
	}
	if opts.Client.AuthSource() != "docker credentials" {
		t.Fatalf("auth source = %q", opts.Client.AuthSource())
	}
}

func TestSetupVerification(t *testing.T) {
	isolate(t)
	r := ocitest.New()
	ocitest.Seed(r)
	host := r.Start(t)

	opts, _, _, err := runSetup(t, host)
	if err != nil {
		t.Fatal(err)
	}
	if opts.Verifier == nil || opts.Verifier.Source() != "Sigstore public good" {
		t.Fatalf("default verifier = %+v", opts.Verifier)
	}

	opts, _, _, err = runSetup(t, "--no-verify", host)
	if err != nil || opts.Verifier != nil {
		t.Fatalf("--no-verify: err=%v verifier=%v", err, opts.Verifier)
	}

	s, err := sigtest.New()
	if err != nil {
		t.Fatal(err)
	}
	rootJSON, err := s.TrustedRootJSON()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "trusted_root.json")
	if err := os.WriteFile(path, rootJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	opts, _, _, err = runSetup(t, "--sigstore-root", path, host)
	if err != nil || opts.Verifier == nil || opts.Verifier.Source() != "trusted_root.json" {
		t.Fatalf("--sigstore-root: err=%v verifier=%v", err, opts.Verifier)
	}

	if _, _, _, err := runSetup(t, "--sigstore-root", filepath.Join(t.TempDir(), "missing.json"), host); err == nil {
		t.Fatal("a missing trusted root should fail")
	}
	if _, _, _, err := runSetup(t, "--no-verify", "--sigstore-root", path, host); err == nil || !strings.Contains(err.Error(), "exclude each other") {
		t.Fatalf("conflicting flags: %v", err)
	}
}
