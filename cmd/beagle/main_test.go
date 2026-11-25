package main

import "testing"

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
