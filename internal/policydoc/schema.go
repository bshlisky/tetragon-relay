package policydoc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"

	tetragoncrd "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0"
)

const schemaResourceURL = "mem://tetragon/v1.8.0/tracingpolicy-schema.json"

var (
	schemaOnce   sync.Once
	schemaCached *jsonschema.Schema
	schemaErr    error
)

// tracingPolicySchema lazily compiles the closed TracingPolicy JSON Schema
// (step 2 prompt Part B3). Compilation happens once per process; the
// embedded schema is fixed at build time, so there is nothing to
// invalidate.
func tracingPolicySchema() (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		schemaCached, schemaErr = compileTracingPolicySchema(tetragoncrd.TracingPoliciesCRD)
	})
	return schemaCached, schemaErr
}

// compileTracingPolicySchema extracts spec.versions[0].schema.openAPIV3Schema
// from the vendored CRD, closes it (B3: "treat the schema as CLOSED"), and
// compiles it. Exported indirectly via tracingPolicySchema for the real
// embedded CRD, and called directly by tests with synthetic CRDs.
func compileTracingPolicySchema(crd []byte) (*jsonschema.Schema, error) {
	var root interface{}
	if err := yaml.Unmarshal(crd, &root); err != nil {
		return nil, fmt.Errorf("policydoc: parse vendored CRD: %w", err)
	}

	openAPISchema, err := extractOpenAPIV3Schema(root)
	if err != nil {
		return nil, err
	}

	closeSchema(openAPISchema)

	schemaJSON, err := json.Marshal(openAPISchema)
	if err != nil {
		return nil, fmt.Errorf("policydoc: marshal closed schema: %w", err)
	}

	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(schemaResourceURL, bytes.NewReader(schemaJSON)); err != nil {
		return nil, fmt.Errorf("policydoc: add schema resource: %w", err)
	}
	schema, err := compiler.Compile(schemaResourceURL)
	if err != nil {
		return nil, fmt.Errorf("policydoc: compile schema: %w", err)
	}
	return schema, nil
}

// extractOpenAPIV3Schema navigates a decoded CustomResourceDefinition
// document to spec.versions[0].schema.openAPIV3Schema, the schema for the
// resource body (apiVersion/kind/metadata/spec). Every step is checked
// explicitly rather than blindly type-asserted, since a malformed or
// unexpected vendored file must fail loudly at startup, not panic.
func extractOpenAPIV3Schema(root interface{}) (map[string]interface{}, error) {
	rootMap, ok := root.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: CRD document is not a mapping", ErrSchemaValidation)
	}
	spec, ok := rootMap["spec"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: CRD .spec is missing or not a mapping", ErrSchemaValidation)
	}
	versions, ok := spec["versions"].([]interface{})
	if !ok || len(versions) == 0 {
		return nil, fmt.Errorf("%w: CRD .spec.versions is missing or empty", ErrSchemaValidation)
	}
	v0, ok := versions[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: CRD .spec.versions[0] is not a mapping", ErrSchemaValidation)
	}
	if name, _ := v0["name"].(string); name != "v1alpha1" {
		return nil, fmt.Errorf("%w: CRD .spec.versions[0].name is %q, want v1alpha1", ErrSchemaValidation, name)
	}
	schemaField, ok := v0["schema"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: CRD .spec.versions[0].schema is missing or not a mapping", ErrSchemaValidation)
	}
	openAPISchema, ok := schemaField["openAPIV3Schema"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: CRD .spec.versions[0].schema.openAPIV3Schema is missing or not a mapping", ErrSchemaValidation)
	}
	return openAPISchema, nil
}

// closeSchema recursively mutates an OpenAPI v3 / JSON Schema document so
// that every object-shaped schema node (one with a "properties" keyword)
// that does not already declare "additionalProperties" gets
// "additionalProperties: false" injected.
//
// Why this is needed (step 2 prompt Part B3, item 12 of the report):
// controller-gen (which generates this CRD) relies on Kubernetes'
// structural-schema *pruning* semantics, where fields absent from
// "properties" are silently dropped rather than rejected, unless
// "x-kubernetes-preserve-unknown-fields: true" is set. A standards-compliant
// JSON Schema validator (this one) does not prune: per the JSON Schema
// spec, "additionalProperties" defaults to true when absent, meaning any
// object-shaped node in this CRD with "properties" but no explicit
// "additionalProperties" would, if compiled unmodified, silently ACCEPT
// arbitrary extra sibling keys instead of either pruning or rejecting them.
// That is strictly worse than Kubernetes' own behavior and is exactly the
// "upstream allows additional properties" case the prompt requires closing.
//
// Schema nodes that already declare "additionalProperties" (as a
// sub-schema, e.g. Kubernetes' `map[string]string`-shaped label maps) are
// left untouched: those are legitimate open-ended maps, not structs with
// unknown extra fields, and constraining their *values*' shape is already
// what their existing "additionalProperties" sub-schema does.
func closeSchema(node interface{}) {
	switch v := node.(type) {
	case map[string]interface{}:
		for _, child := range v {
			closeSchema(child)
		}
		if _, hasProperties := v["properties"]; hasProperties {
			if _, hasAdditional := v["additionalProperties"]; !hasAdditional {
				v["additionalProperties"] = false
			}
		}
	case []interface{}:
		for _, child := range v {
			closeSchema(child)
		}
	}
}

// validateAgainstSchema validates a decoded JSON value (produced with
// json.Decoder.UseNumber so integers are not lossily routed through
// float64) against the closed TracingPolicy schema.
func validateAgainstSchema(v interface{}) error {
	schema, err := tracingPolicySchema()
	if err != nil {
		return fmt.Errorf("policydoc: schema unavailable: %w", err)
	}
	if err := schema.Validate(v); err != nil {
		return fmt.Errorf("%w: %w", ErrSchemaValidation, err)
	}
	return nil
}
