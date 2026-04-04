package github

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUploadSARIFPostsCanonicalPayload(t *testing.T) {
	var body string
	var method string
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		path = r.URL.Path
		data, _ := io.ReadAll(r.Body)
		body = string(data)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"upload-1"}`))
	}))
	defer server.Close()

	client, err := NewClient("ghs-test", server.Client())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	client.baseURL = server.URL

	repo := Repository{Owner: "batu3384", Name: "ironsentinel"}
	err = client.UploadSARIF(context.Background(), repo, SARIFUploadRequest{
		CommitSHA: "abc123",
		Ref:       "refs/heads/main",
		SARIF:     `{"version":"2.1.0"}`,
		Category:  "ironsentinel/run-1",
	})
	if err != nil {
		t.Fatalf("upload sarif: %v", err)
	}
	if method != http.MethodPost {
		t.Fatalf("expected POST request, got %s", method)
	}
	if path != "/repos/batu3384/ironsentinel/code-scanning/sarifs" {
		t.Fatalf("expected exact SARIF path, got %s", path)
	}
	if !strings.Contains(body, `"commit_sha":"abc123"`) {
		t.Fatalf("expected commit sha in request body: %s", body)
	}
	if !strings.Contains(body, `"sarif":"eyJ2ZXJzaW9uIjoiMi4xLjAifQ=="`) {
		t.Fatalf("expected base64 sarif payload in request body: %s", body)
	}
	if !strings.Contains(body, `"category":"ironsentinel/run-1"`) {
		t.Fatalf("expected category in request body: %s", body)
	}
}

func TestUploadSARIFMapsNonAcceptedResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"bad request"}`))
	}))
	defer server.Close()

	client, err := NewClient("ghs-test", server.Client())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	client.baseURL = server.URL

	err = client.UploadSARIF(context.Background(), Repository{Owner: "batu3384", Name: "ironsentinel"}, SARIFUploadRequest{
		CommitSHA: "abc123",
		Ref:       "refs/heads/main",
		SARIF:     `{"version":"2.1.0"}`,
	})
	if err == nil || !strings.Contains(err.Error(), "sarif upload failed") || !strings.Contains(err.Error(), "bad request") {
		t.Fatalf("expected mapped upload error, got %v", err)
	}
}
