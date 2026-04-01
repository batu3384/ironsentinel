package agent

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSeedOSVMirrorDownloadsConfiguredEcosystems(t *testing.T) {
	originalClient := mirrorHTTPClient
	defer func() { mirrorHTTPClient = originalClient }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/all.zip") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("zip-bytes"))
	}))
	defer server.Close()

	originalEcosystems := osvMirrorEcosystems
	defer func() { osvMirrorEcosystems = originalEcosystems }()
	osvMirrorEcosystems = []string{"Go", "PyPI"}
	mirrorHTTPClient = server.Client()

	root := t.TempDir()
	downloadMirrorFileOriginal := downloadMirrorFileBaseURL
	defer func() { downloadMirrorFileBaseURL = downloadMirrorFileOriginal }()
	downloadMirrorFileBaseURL = server.URL

	if err := seedOSVMirror(root); err != nil {
		t.Fatalf("seed OSV mirror: %v", err)
	}

	for _, ecosystem := range osvMirrorEcosystems {
		path := filepath.Join(root, "osv-scanner", ecosystem, "all.zip")
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected mirror file for %s: %v", ecosystem, err)
		}
	}
}
