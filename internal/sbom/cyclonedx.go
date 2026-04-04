package sbom

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/batu3384/ironsentinel/internal/domain"
)

type Component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
	Type    string `json:"type"`
}

type cyclonedxDocument struct {
	Components []Component `json:"components"`
}

func ComponentsFromArtifacts(artifacts []domain.ArtifactRef) []Component {
	components := make([]Component, 0)
	for _, artifact := range artifacts {
		if artifact.Kind != "sbom" || strings.TrimSpace(artifact.URI) == "" || artifact.URI == "inline" {
			continue
		}
		body, err := os.ReadFile(artifact.URI)
		if err != nil {
			continue
		}
		var document cyclonedxDocument
		if err := json.Unmarshal(body, &document); err != nil {
			continue
		}
		components = append(components, document.Components...)
	}
	return components
}

func ProductsByComponentName(artifacts []domain.ArtifactRef) map[string][]string {
	index := make(map[string][]string)
	for _, component := range ComponentsFromArtifacts(artifacts) {
		name := strings.TrimSpace(component.Name)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		purl := strings.TrimSpace(component.PURL)
		if purl == "" {
			continue
		}
		index[key] = appendUnique(index[key], purl)
	}
	return index
}

func appendUnique(values []string, next string) []string {
	for _, value := range values {
		if value == next {
			return values
		}
	}
	return append(values, next)
}
