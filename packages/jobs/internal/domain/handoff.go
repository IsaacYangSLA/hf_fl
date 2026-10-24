package domain

// CollectedArtifact is a trusted collector receipt shared by execution and
// retention. Locator is opaque to the executor; download authorization must
// validate the separate structured ArtifactLocator before resolving content.
type CollectedArtifact struct {
	Path      string         `json:"path"`
	Locator   string         `json:"locator"`
	Kind      string         `json:"kind,omitempty"`
	SHA256    string         `json:"sha256"`
	SizeBytes int64          `json:"size_bytes"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}
