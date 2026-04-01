package release

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
)

type BundleLock struct {
	Version       int                   `json:"version"`
	GeneratedAt   string                `json:"generatedAt,omitempty"`
	Signing       TrustAnchor           `json:"signing,omitempty"`
	TrustedAssets []TrustedAsset        `json:"trustedAssets,omitempty"`
	Channels      map[string][]LockSpec `json:"channels"`
}

type LockSpec struct {
	Name             string            `json:"name"`
	Version          string            `json:"version"`
	PlatformVersions map[string]string `json:"platformVersions,omitempty"`
	Source           string            `json:"source,omitempty"`
	Checksums        map[string]string `json:"checksums,omitempty"`
	Signature        BundleSignature   `json:"signature,omitempty"`
	SourceIntegrity  SourceIntegrity   `json:"sourceIntegrity,omitempty"`
}

type BundleSignature struct {
	Value  string `json:"value,omitempty"`
	Signer string `json:"signer,omitempty"`
}

type TrustedAsset struct {
	Name      string          `json:"name"`
	Kind      string          `json:"kind,omitempty"`
	Path      string          `json:"path"`
	SHA256    string          `json:"sha256,omitempty"`
	Signature BundleSignature `json:"signature,omitempty"`
}

type SourceIntegrity struct {
	Kind      string `json:"kind,omitempty"`
	URL       string `json:"url,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	Digest    string `json:"digest,omitempty"`
}

func LoadBundleLock(path string) (BundleLock, error) {
	payload := BundleLock{Channels: make(map[string][]LockSpec)}
	bytes, err := os.ReadFile(path)
	if err != nil {
		return payload, err
	}
	if err := json.Unmarshal(bytes, &payload); err != nil {
		return BundleLock{}, err
	}
	if payload.Channels == nil {
		payload.Channels = make(map[string][]LockSpec)
	}
	return payload, nil
}

func WriteBundleLock(path string, lock BundleLock) error {
	if lock.Channels == nil {
		lock.Channels = make(map[string][]LockSpec)
	}
	for channel, specs := range lock.Channels {
		sort.Slice(specs, func(i, j int) bool {
			if specs[i].Name == specs[j].Name {
				return specs[i].Version < specs[j].Version
			}
			return specs[i].Name < specs[j].Name
		})
		for index := range specs {
			specs[index].Name = strings.TrimSpace(specs[index].Name)
			specs[index].Version = strings.TrimSpace(specs[index].Version)
			for platform, version := range specs[index].PlatformVersions {
				specs[index].PlatformVersions[platform] = strings.TrimSpace(version)
			}
			specs[index].Source = strings.TrimSpace(specs[index].Source)
		}
		lock.Channels[channel] = specs
	}
	body, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return os.WriteFile(path, body, 0o644)
}
