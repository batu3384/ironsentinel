package agent

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

var protectedArtifactKinds = []string{"evidence", "report", "raw-output", "sbom"}

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

type artifactProtector struct {
	retentionDays int
	redaction     bool
	key           []byte
}

type artifactEncryptionEnvelope struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func newArtifactProtector(cfg config.Config) artifactProtector {
	var key []byte
	if strings.TrimSpace(cfg.ArtifactEncryptionKey) != "" {
		sum := sha256.Sum256([]byte(cfg.ArtifactEncryptionKey))
		key = sum[:]
	}
	return artifactProtector{
		retentionDays: cfg.ArtifactRetentionDays,
		redaction:     cfg.ArtifactRedaction,
		key:           key,
	}
}

func discoverArtifactProtection(cfg config.Config) domain.RuntimeArtifactProtection {
	return domain.RuntimeArtifactProtection{
		RetentionDays:     cfg.ArtifactRetentionDays,
		RedactionEnabled:  cfg.ArtifactRedaction,
		EncryptionEnabled: strings.TrimSpace(cfg.ArtifactEncryptionKey) != "",
		ProtectedKinds:    append([]string(nil), protectedArtifactKinds...),
	}
}

func (p artifactProtector) protect(kind, filename string, body []byte) (string, []byte, bool, bool, *time.Time, error) {
	protected := append([]byte(nil), body...)
	redacted := false
	if p.redaction {
		redactedBody := redactSensitiveBody(protected)
		redacted = string(redactedBody) != string(protected)
		protected = redactedBody
	}

	encrypted := false
	if p.shouldEncrypt(kind) {
		encryptedBody, err := encryptArtifactBody(protected, p.key)
		if err != nil {
			return "", nil, false, false, nil, err
		}
		protected = encryptedBody
		filename += ".enc"
		encrypted = true
	}

	return filename, protected, redacted, encrypted, p.expiresAt(), nil
}

func (p artifactProtector) shouldEncrypt(kind string) bool {
	if len(p.key) == 0 {
		return false
	}
	for _, candidate := range protectedArtifactKinds {
		if candidate == kind {
			return true
		}
	}
	return false
}

func (p artifactProtector) expiresAt() *time.Time {
	if p.retentionDays <= 0 {
		return nil
	}
	expires := time.Now().UTC().Add(time.Duration(p.retentionDays) * 24 * time.Hour)
	return &expires
}

func redactSensitiveBody(body []byte) []byte {
	if len(body) == 0 {
		return body
	}
	text := string(body)
	for _, redactor := range artifactRedactors {
		text = redactor.pattern.ReplaceAllString(text, redactor.replacement)
	}
	return []byte(text)
}

func encryptArtifactBody(body, key []byte) ([]byte, error) {
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
	envelope := artifactEncryptionEnvelope{
		Version:    1,
		Algorithm:  "AES-256-GCM",
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	return json.MarshalIndent(envelope, "", "  ")
}

func pruneExpiredArtifactRuns(outputDir string, retentionDays int) error {
	if retentionDays <= 0 {
		return nil
	}
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	cutoff := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		_ = os.RemoveAll(filepath.Join(outputDir, entry.Name()))
	}
	return nil
}
