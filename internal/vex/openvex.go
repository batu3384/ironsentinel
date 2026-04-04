package vex

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/batu3384/ironsentinel/internal/domain"
)

const openVEXContext = "https://openvex.dev/ns/v0.2.0"

type Document struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id,omitempty"`
	Author     string      `json:"author,omitempty"`
	Role       string      `json:"role,omitempty"`
	Timestamp  time.Time   `json:"timestamp"`
	Version    int         `json:"version"`
	Statements []Statement `json:"statements"`
}

type Statement struct {
	Vulnerability struct {
		Name string `json:"name"`
	} `json:"vulnerability"`
	Products      []Product        `json:"products"`
	Status        domain.VEXStatus `json:"status"`
	Justification string           `json:"justification,omitempty"`
}

type Product struct {
	ID string `json:"@id"`
}

func ParseOpenVEX(body []byte) (Document, error) {
	var doc Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return Document{}, err
	}
	if strings.TrimSpace(doc.Context) == "" {
		doc.Context = openVEXContext
	}
	if len(doc.Statements) == 0 {
		return Document{}, fmt.Errorf("openvex statements are required")
	}
	if doc.Version == 0 {
		doc.Version = 1
	}
	return doc, nil
}

func Apply(findings []domain.Finding, doc Document, sbomProducts map[string][]string) ([]domain.Finding, domain.VEXSummary) {
	applied := make([]domain.Finding, 0, len(findings))
	summary := domain.VEXSummary{
		Source:       doc.ID,
		StatusCounts: make(map[domain.VEXStatus]int),
	}
	for _, finding := range findings {
		next := finding
		for _, statement := range doc.Statements {
			if !statementMatchesFinding(statement, finding, sbomProducts) {
				continue
			}
			next.VEXStatus = statement.Status
			next.VEXJustification = strings.TrimSpace(statement.Justification)
			next.VEXStatementSource = doc.ID
			summary.AppliedCount++
			summary.StatusCounts[statement.Status]++
			break
		}
		applied = append(applied, next)
	}
	return applied, summary
}

func statementMatchesFinding(statement Statement, finding domain.Finding, sbomProducts map[string][]string) bool {
	if finding.Category != domain.CategorySCA {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(statement.Vulnerability.Name), strings.TrimSpace(finding.RuleID)) {
		return false
	}
	location := strings.ToLower(strings.TrimSpace(finding.Location))
	if location == "" {
		return false
	}
	candidates := append([]string(nil), sbomProducts[location]...)
	if len(candidates) == 0 {
		candidates = append(candidates, "pkg:generic/"+location)
	}
	for _, product := range statement.Products {
		value := strings.TrimSpace(product.ID)
		if value == "" {
			continue
		}
		for _, candidate := range candidates {
			if strings.EqualFold(value, candidate) || productContainsComponent(value, location) {
				return true
			}
		}
	}
	return false
}

func productContainsComponent(productID, component string) bool {
	value := strings.ToLower(strings.TrimSpace(productID))
	component = strings.ToLower(strings.TrimSpace(component))
	if value == "" || component == "" {
		return false
	}
	return strings.Contains(value, "/"+component+"@") ||
		strings.HasSuffix(value, "/"+component) ||
		strings.Contains(value, "/"+component+"?") ||
		strings.Contains(value, ":"+component+"@")
}

func SuppressesFinding(finding domain.Finding) bool {
	switch finding.VEXStatus {
	case domain.VEXStatusNotAffected, domain.VEXStatusFixed:
		return true
	default:
		return false
	}
}
