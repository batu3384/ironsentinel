package evidence

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
)

var ProtectedKinds = []string{"evidence", "report", "raw-output", "sbom"}

var artifactRedactors = []struct {
	pattern     *regexp.Regexp
	replacement string
}{
	{
		pattern:     regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`),
		replacement: "[REDACTED_GITHUB_TOKEN]",
	},
	{
		pattern:     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		replacement: "[REDACTED_AWS_ACCESS_KEY]",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._-]+`),
		replacement: "$1[REDACTED_BEARER_TOKEN]",
	},
	{
		pattern:     regexp.MustCompile(`(?i)((secret|token|password|api[_-]?key)\s*[:=]\s*["'])[^"'\n]{8,}(["'])`),
		replacement: "$1[REDACTED_SECRET]$3",
	},
}

type Policy struct {
	RetentionDays     int
	RedactionEnabled  bool
	EncryptionEnabled bool
	ProtectedKinds    []string
	key               []byte
}

type encryptionEnvelope struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func PolicyFromConfig(cfg config.Config) Policy {
	var key []byte
	if strings.TrimSpace(cfg.ArtifactEncryptionKey) != "" {
		sum := sha256.Sum256([]byte(cfg.ArtifactEncryptionKey))
		key = sum[:]
	}
	return Policy{
		RetentionDays:     cfg.ArtifactRetentionDays,
		RedactionEnabled:  cfg.ArtifactRedaction,
		EncryptionEnabled: len(key) > 0,
		ProtectedKinds:    append([]string(nil), ProtectedKinds...),
		key:               key,
	}
}

func RuntimeProtection(cfg config.Config) domain.RuntimeArtifactProtection {
	policy := PolicyFromConfig(cfg)
	return domain.RuntimeArtifactProtection{
		RetentionDays:     policy.RetentionDays,
		RedactionEnabled:  policy.RedactionEnabled,
		EncryptionEnabled: policy.EncryptionEnabled,
		ProtectedKinds:    append([]string(nil), policy.ProtectedKinds...),
	}
}

func (p Policy) Protect(kind, filename string, body []byte) (string, []byte, bool, bool, *time.Time, error) {
	protected := append([]byte(nil), body...)
	redacted := false
	if p.RedactionEnabled {
		redactedBody := redactBody(protected)
		redacted = string(redactedBody) != string(protected)
		protected = redactedBody
	}

	encrypted := false
	if p.shouldEncrypt(kind) {
		encryptedBody, err := encryptBody(protected, p.key)
		if err != nil {
			return "", nil, false, false, nil, err
		}
		protected = encryptedBody
		filename += ".enc"
		encrypted = true
	}

	return filename, protected, redacted, encrypted, p.expiresAt(), nil
}

func (p Policy) WriteFile(targetPath, kind, label string, body []byte) (domain.ArtifactRef, error) {
	filename, protectedBody, redacted, encrypted, expiresAt, err := p.Protect(kind, filepath.Base(targetPath), body)
	if err != nil {
		return domain.ArtifactRef{}, err
	}
	finalPath := filepath.Join(filepath.Dir(targetPath), filename)
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o755); err != nil {
		return domain.ArtifactRef{}, err
	}
	if err := os.WriteFile(finalPath, protectedBody, 0o644); err != nil {
		return domain.ArtifactRef{}, err
	}
	if err := os.Chmod(finalPath, 0o600); err != nil {
		return domain.ArtifactRef{}, err
	}
	absolute, err := filepath.Abs(finalPath)
	if err != nil {
		return domain.ArtifactRef{}, err
	}
	return domain.ArtifactRef{
		Kind:      kind,
		Label:     label,
		URI:       absolute,
		Redacted:  redacted,
		Encrypted: encrypted,
		ExpiresAt: expiresAt,
	}, nil
}

func (p Policy) shouldEncrypt(kind string) bool {
	if !p.EncryptionEnabled || len(p.key) == 0 {
		return false
	}
	for _, candidate := range p.ProtectedKinds {
		if candidate == kind {
			return true
		}
	}
	return false
}

func (p Policy) expiresAt() *time.Time {
	if p.RetentionDays <= 0 {
		return nil
	}
	expires := time.Now().UTC().Add(time.Duration(p.RetentionDays) * 24 * time.Hour)
	return &expires
}

func redactBody(body []byte) []byte {
	if len(body) == 0 {
		return body
	}
	text := string(body)
	for _, redactor := range artifactRedactors {
		text = redactor.pattern.ReplaceAllString(text, redactor.replacement)
	}
	return []byte(text)
}

func encryptBody(body, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, body, nil)
	envelope := encryptionEnvelope{
		Version:    1,
		Algorithm:  "AES-256-GCM",
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	return json.MarshalIndent(envelope, "", "  ")
}
