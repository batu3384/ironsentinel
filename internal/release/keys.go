package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type GeneratedKeyPair struct {
	Type       string `json:"type"`
	Signer     string `json:"signer"`
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

func GenerateKeyPair(signer string) (GeneratedKeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return GeneratedKeyPair{}, err
	}
	return GeneratedKeyPair{
		Type:       "ed25519",
		Signer:     signer,
		PublicKey:  base64.StdEncoding.EncodeToString(publicKey),
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey),
	}, nil
}

func PublicKeyFromPrivateKey(privateKeyB64 string) (string, error) {
	raw := strings.TrimSpace(privateKeyB64)
	if raw == "" {
		return "", fmt.Errorf("private key is empty")
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", err
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid private key length")
	}
	publicKey := ed25519.PrivateKey(decoded).Public().(ed25519.PublicKey)
	return base64.StdEncoding.EncodeToString(publicKey), nil
}

func (pair GeneratedKeyPair) LockJSON() ([]byte, error) {
	return json.MarshalIndent(map[string]any{
		"version": 1,
		"signing": map[string]any{
			"type":      pair.Type,
			"signer":    pair.Signer,
			"publicKey": pair.PublicKey,
		},
		"channels": map[string]any{},
	}, "", "  ")
}
