// Package meta defines registry-specific tag metadata that the OCI
// distribution API does not provide, such as push and pull times or
// vulnerability scan results. Vendor clients (Harbor, Docker Hub, ...)
// implement Provider; beagle works without any provider.
package meta

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// TagInfo is what a registry knows about a tag beyond the manifest.
type TagInfo struct {
	Digest string
	Pushed time.Time
	// Pulled is the zero time if the tag was never pulled (or unknown).
	Pulled time.Time
	// Signatures lists signature formats the registry reports, e.g. "cosign".
	Signatures []string
	// Attached lists other attachments the registry reports, e.g. "sbom".
	Attached []string
	// Vulns is the vulnerability scan summary, nil if not available.
	Vulns *Vulns
}

// Vulns summarizes a vulnerability scan.
type Vulns struct {
	// Status is the scan status as reported by the registry, e.g. "Success".
	Status   string
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
	Scanner  string
}

// Done reports whether the scan finished successfully.
func (v *Vulns) Done() bool {
	return v != nil && (v.Status == "" || strings.EqualFold(v.Status, "success"))
}

// String renders a compact summary such as "C1 H3 M7" or "clean".
func (v *Vulns) String() string {
	if v == nil {
		return "-"
	}
	if !v.Done() {
		return strings.ToLower(v.Status)
	}
	var parts []string
	for _, p := range []struct {
		label string
		n     int
	}{{"C", v.Critical}, {"H", v.High}, {"M", v.Medium}, {"L", v.Low}, {"U", v.Unknown}} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%s%d", p.label, p.n))
		}
	}
	if len(parts) == 0 {
		return "clean"
	}
	return strings.Join(parts, " ")
}

// Capabilities tells the UI which TagInfo fields a provider fills, so it can
// pick the columns to show.
type Capabilities struct {
	Pushed     bool
	Pulled     bool
	Signatures bool
	Vulns      bool
}

// Provider returns vendor metadata for all tags of a repository in bulk.
type Provider interface {
	// Name identifies the provider in the UI, e.g. "harbor".
	Name() string
	Capabilities() Capabilities
	// Tags returns metadata keyed by tag name. Missing tags are fine.
	Tags(ctx context.Context, repo string) (map[string]TagInfo, error)
}
