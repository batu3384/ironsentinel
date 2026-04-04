package github

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
)

type SARIFUploadRequest struct {
	CommitSHA string
	Ref       string
	SARIF     string
	Category  string
}

func (c *Client) UploadSARIF(ctx context.Context, repo Repository, req SARIFUploadRequest) error {
	payload := map[string]any{
		"commit_sha": req.CommitSHA,
		"ref":        req.Ref,
		"sarif":      base64.StdEncoding.EncodeToString([]byte(req.SARIF)),
	}
	if req.Category != "" {
		payload["category"] = req.Category
	}

	resp, err := c.postJSON(ctx, fmt.Sprintf("/repos/%s/%s/code-scanning/sarifs", repo.Owner, repo.Name), payload)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusAccepted {
		return mapHTTPError("sarif upload", repo, resp)
	}
	_ = readBody(resp)
	return nil
}

func mapHTTPError(operation string, repo Repository, resp *http.Response) error {
	body := readBody(resp)
	if body == "" && resp != nil {
		body = resp.Status
	}
	return fmt.Errorf("%s failed for %s/%s: %s", operation, repo.Owner, repo.Name, body)
}
