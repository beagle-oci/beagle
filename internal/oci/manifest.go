package oci

import (
	"encoding/json"
	"fmt"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Media types that are not part of the OCI image spec but common in the wild.
const (
	MediaTypeDockerManifest     = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeDockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaTypeDockerConfig       = "application/vnd.docker.container.image.v1+json"
	MediaTypeArtifactManifest   = "application/vnd.oci.artifact.manifest.v1+json"
)

// Manifest is a parsed image manifest or image index. Fields that do not
// apply to the concrete type are left empty.
type Manifest struct {
	Descriptor   ocispec.Descriptor
	Raw          []byte
	MediaType    string
	ArtifactType string
	Config       *ocispec.Descriptor
	// Layers holds image layers, or the blobs of an artifact manifest.
	Layers []ocispec.Descriptor
	// Manifests holds the entries of an image index.
	Manifests   []ocispec.Descriptor
	Subject     *ocispec.Descriptor
	Annotations map[string]string
}

type rawManifest struct {
	SchemaVersion int                  `json:"schemaVersion"`
	MediaType     string               `json:"mediaType"`
	ArtifactType  string               `json:"artifactType"`
	Config        *ocispec.Descriptor  `json:"config"`
	Layers        []ocispec.Descriptor `json:"layers"`
	Blobs         []ocispec.Descriptor `json:"blobs"`
	Manifests     []ocispec.Descriptor `json:"manifests"`
	Subject       *ocispec.Descriptor  `json:"subject"`
	Annotations   map[string]string    `json:"annotations"`
}

// ParseManifest parses raw manifest bytes. desc is the descriptor the
// manifest was fetched with; its media type wins over the one in the body.
func ParseManifest(desc ocispec.Descriptor, raw []byte) (*Manifest, error) {
	var rm rawManifest
	if err := json.Unmarshal(raw, &rm); err != nil {
		return nil, fmt.Errorf("parse manifest %s: %w", desc.Digest, err)
	}
	mediaType := desc.MediaType
	if mediaType == "" {
		mediaType = rm.MediaType
	}
	if mediaType == "" {
		if len(rm.Manifests) > 0 {
			mediaType = ocispec.MediaTypeImageIndex
		} else {
			mediaType = ocispec.MediaTypeImageManifest
		}
	}
	desc.MediaType = mediaType

	m := &Manifest{
		Descriptor:   desc,
		Raw:          raw,
		MediaType:    mediaType,
		ArtifactType: rm.ArtifactType,
		Config:       rm.Config,
		Layers:       rm.Layers,
		Manifests:    rm.Manifests,
		Subject:      rm.Subject,
		Annotations:  rm.Annotations,
	}
	if len(m.Layers) == 0 && len(rm.Blobs) > 0 {
		m.Layers = rm.Blobs
	}
	return m, nil
}

// IsIndex reports whether the manifest is an image index / manifest list.
func (m *Manifest) IsIndex() bool {
	return IsIndexMediaType(m.MediaType)
}

// EffectiveArtifactType returns the artifact type as defined by the image
// spec: the artifactType field, or the config media type for artifacts that
// predate the field.
func (m *Manifest) EffectiveArtifactType() string {
	if m.ArtifactType != "" {
		return m.ArtifactType
	}
	if m.Config == nil {
		return ""
	}
	switch m.Config.MediaType {
	case ocispec.MediaTypeImageConfig, MediaTypeDockerConfig, ocispec.MediaTypeEmptyJSON, "":
		return ""
	}
	return m.Config.MediaType
}

// ContentSize returns the size of everything the manifest references
// directly (config and layers), not including the manifest itself.
func (m *Manifest) ContentSize() int64 {
	var total int64
	if m.Config != nil {
		total += m.Config.Size
	}
	for _, l := range m.Layers {
		total += l.Size
	}
	return total
}

// IsIndexMediaType reports whether mediaType denotes an index.
func IsIndexMediaType(mediaType string) bool {
	return mediaType == ocispec.MediaTypeImageIndex || mediaType == MediaTypeDockerManifestList
}

// IsManifestMediaType reports whether mediaType denotes any kind of manifest
// (as opposed to a blob).
func IsManifestMediaType(mediaType string) bool {
	switch mediaType {
	case ocispec.MediaTypeImageManifest, ocispec.MediaTypeImageIndex,
		MediaTypeDockerManifest, MediaTypeDockerManifestList, MediaTypeArtifactManifest:
		return true
	}
	return false
}

// PlatformString renders a platform as os/arch[/variant].
func PlatformString(p *ocispec.Platform) string {
	if p == nil {
		return ""
	}
	parts := []string{p.OS, p.Architecture}
	if p.Variant != "" {
		parts = append(parts, p.Variant)
	}
	return strings.Join(parts, "/")
}
