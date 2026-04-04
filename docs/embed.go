// Package docs embeds the OpenAPI specification for the Wiremind API.
package docs

import _ "embed"

// OpenAPISpec is the raw OpenAPI 3.0.3 YAML specification.
//
//go:embed openapi.yaml
var OpenAPISpec []byte
