package connector

import (
	"bytes"
	"io"
	"net/http"

	azruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"google.golang.org/api/googleapi"
)

// HTTPError uses the official decoder for raw-response Finding adapters.
// Successful payloads remain byte-preserving; failure bodies are bounded and
// never returned to the caller or written to logs.
func HTTPError(provider, api string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var err error
	switch provider {
	case "azure":
		copy := *resp
		copy.Body = io.NopCloser(bytes.NewReader(body))
		err = azruntime.NewResponseError(&copy)
	case "gcp":
		err = googleapi.CheckResponseWithBody(resp, body)
	}
	if err == nil {
		return &Error{Provider: provider, SourceAPI: api, HTTPStatus: resp.StatusCode, Kind: httpErrorKind(resp.StatusCode)}
	}
	return WithSourceAPI(provider, api, err)
}
