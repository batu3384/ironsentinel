package github

import "strings"

type CustomPatternSource struct {
	RuleID      string
	Title       string
	Description string
	Pattern     string
}

type CustomPatternManifest struct {
	Version  string          `json:"version"`
	Patterns []CustomPattern `json:"patterns"`
}

type CustomPattern struct {
	Name           string `json:"name"`
	Description    string `json:"description,omitempty"`
	SecretFormat   string `json:"secret_format"`
	BeforeSecret   string `json:"before_secret,omitempty"`
	AfterSecret    string `json:"after_secret,omitempty"`
	PushProtection bool   `json:"push_protection,omitempty"`
}

func BuildCustomPatternManifest(sources []CustomPatternSource) CustomPatternManifest {
	patterns := make([]CustomPattern, 0, len(sources))
	for _, source := range sources {
		if strings.TrimSpace(source.Pattern) == "" {
			continue
		}
		patterns = append(patterns, CustomPattern{
			Name:           "IronSentinel / " + strings.TrimSpace(source.RuleID),
			Description:    coalesce(source.Description, source.Title),
			SecretFormat:   strings.TrimSpace(source.Pattern),
			BeforeSecret:   `\A|[^0-9A-Za-z_]`,
			AfterSecret:    `\z|[^0-9A-Za-z_]`,
			PushProtection: true,
		})
	}
	return CustomPatternManifest{
		Version:  "1",
		Patterns: patterns,
	}
}

func coalesce(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
