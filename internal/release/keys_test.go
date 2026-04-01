package release

import "testing"

func TestGenerateKeyPairProducesLockMaterial(t *testing.T) {
	pair, err := GenerateKeyPair("smoke-root")
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	if pair.Type != "ed25519" || pair.Signer != "smoke-root" {
		t.Fatalf("unexpected key pair metadata: %+v", pair)
	}
	if pair.PublicKey == "" || pair.PrivateKey == "" {
		t.Fatalf("expected populated key material")
	}

	lockBytes, err := pair.LockJSON()
	if err != nil {
		t.Fatalf("lock json: %v", err)
	}
	if len(lockBytes) == 0 {
		t.Fatalf("expected non-empty lock json")
	}
}
