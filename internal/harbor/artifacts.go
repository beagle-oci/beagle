package harbor

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/beagle-oci/beagle/internal/meta"
)

// Artifact is an entry of the Harbor artifacts API. Only the fields beagle
// uses are decoded.
type Artifact struct {
	Digest   string    `json:"digest"`
	Size     int64     `json:"size"`
	PushTime time.Time `json:"push_time"`
	PullTime time.Time `json:"pull_time"`
	Tags     []struct {
		Name     string    `json:"name"`
		PushTime time.Time `json:"push_time"`
		PullTime time.Time `json:"pull_time"`
	} `json:"tags"`
	Accessories []struct {
		Type   string `json:"type"`
		Digest string `json:"digest"`
	} `json:"accessories"`
	// ScanOverview is keyed by report MIME type.
	ScanOverview map[string]ScanSummary `json:"scan_overview"`
}

// ScanSummary is one entry of an artifact's scan overview.
type ScanSummary struct {
	ScanStatus string `json:"scan_status"`
	Severity   string `json:"severity"`
	Summary    *struct {
		Total   int            `json:"total"`
		Fixable int            `json:"fixable"`
		Summary map[string]int `json:"summary"`
	} `json:"summary"`
	Scanner *struct {
		Name string `json:"name"`
	} `json:"scanner"`
}

// vulnerabilityReportTypes asks Harbor for the scan report formats beagle
// understands; the Harbor UI sends the same header.
const vulnerabilityReportTypes = "application/vnd.security.vulnerability.report; version=1.1, " +
	"application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"

// Artifacts lists the artifacts of a repository ("project/name") with tags,
// accessories and scan overview.
func (c *Client) Artifacts(ctx context.Context, repo string) ([]Artifact, error) {
	project, name, ok := strings.Cut(repo, "/")
	if !ok {
		return nil, nil
	}
	// Harbor wants repository names with slashes encoded twice:
	// a/b -> a%2Fb -> a%252Fb.
	path := "/projects/" + url.PathEscape(project) + "/repositories/" + url.PathEscape(url.PathEscape(name)) + "/artifacts"
	extra := url.Values{
		"with_tag":           {"true"},
		"with_accessory":     {"true"},
		"with_scan_overview": {"true"},
	}
	return list[Artifact](ctx, c, path, extra, map[string]string{"X-Accept-Vulnerabilities": vulnerabilityReportTypes})
}

// Name implements meta.Provider.
func (c *Client) Name() string { return "harbor" }

// Capabilities implements meta.Provider.
func (c *Client) Capabilities() meta.Capabilities {
	return meta.Capabilities{Pushed: true, Pulled: true, Signatures: true, Vulns: true}
}

// Tags implements meta.Provider using the artifacts API.
func (c *Client) Tags(ctx context.Context, repo string) (map[string]meta.TagInfo, error) {
	artifacts, err := c.Artifacts(ctx, repo)
	if err != nil {
		return nil, err
	}
	out := map[string]meta.TagInfo{}
	for _, a := range artifacts {
		base := meta.TagInfo{Digest: a.Digest, Pushed: a.PushTime, Pulled: a.PullTime, Vulns: vulns(a.ScanOverview)}
		for _, acc := range a.Accessories {
			t := strings.ToLower(acc.Type)
			switch {
			case strings.HasPrefix(t, "signature."):
				format := strings.TrimPrefix(t, "signature.")
				if !slices.Contains(base.Signatures, format) {
					base.Signatures = append(base.Signatures, format)
				}
			case strings.Contains(t, "sbom"):
				if !slices.Contains(base.Attached, "sbom") {
					base.Attached = append(base.Attached, "sbom")
				}
			}
		}
		slices.Sort(base.Signatures)
		for _, tag := range a.Tags {
			info := base
			if !tag.PushTime.IsZero() {
				info.Pushed = tag.PushTime
			}
			if tag.PullTime.After(info.Pulled) {
				info.Pulled = tag.PullTime
			}
			if info.Pulled.Year() < 2 {
				// Harbor reports "never pulled" as 0001-01-01.
				info.Pulled = time.Time{}
			}
			out[tag.Name] = info
		}
	}
	return out, nil
}

func vulns(overview map[string]ScanSummary) *meta.Vulns {
	for _, s := range overview {
		v := &meta.Vulns{Status: s.ScanStatus}
		if s.Scanner != nil {
			v.Scanner = s.Scanner.Name
		}
		if s.Summary != nil {
			v.Critical = s.Summary.Summary["Critical"]
			v.High = s.Summary.Summary["High"]
			v.Medium = s.Summary.Summary["Medium"]
			v.Low = s.Summary.Summary["Low"]
			v.Unknown = s.Summary.Summary["Unknown"]
		}
		return v
	}
	return nil
}
