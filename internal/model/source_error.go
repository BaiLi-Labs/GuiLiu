package model

// SourceError is the bounded, machine-readable part of a failed source request.
// Messages, bodies, headers, credentials and authorization diagnostics are not
// copied from SDK errors. A denial only describes the request that was made;
// it is not an inventory of all permissions held by a credential.
type SourceError struct {
	Provider   string `json:"provider"`
	Kind       string `json:"kind"`
	Code       string `json:"code,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
	SourceAPI  string `json:"source_api,omitempty"`
}
