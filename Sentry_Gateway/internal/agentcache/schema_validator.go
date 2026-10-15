// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package agentcache

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// ValidatePayload validates a request body against a SkillContract's input_schema.
// The schema is compiled on each call (no persistent state). For hot-path
// performance, callers should only invoke this when X-Cicada-Target-Skill is
// present AND the skill contract has a non-empty InputSchema.
//
// Returns nil if valid, a descriptive error otherwise.
func ValidatePayload(bodyBytes []byte, contract SkillContract) error {
	schemaStr := strings.TrimSpace(contract.InputSchema)
	if schemaStr == "" || schemaStr == "{}" {
		// No schema constraint declared — pass through
		return nil
	}

	// Decode the schema JSON into an interface{} for the compiler
	var schemaDoc interface{}
	if err := json.Unmarshal([]byte(schemaStr), &schemaDoc); err != nil {
		return fmt.Errorf("invalid input_schema in skill contract '%s': %w", contract.SkillName, err)
	}

	// Compile the schema
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("skill-schema.json", schemaDoc); err != nil {
		return fmt.Errorf("failed to add schema resource for skill '%s': %w", contract.SkillName, err)
	}
	schema, err := compiler.Compile("skill-schema.json")
	if err != nil {
		return fmt.Errorf("failed to compile schema for skill '%s': %w", contract.SkillName, err)
	}

	// Decode the request body
	var doc interface{}
	if err := json.Unmarshal(bodyBytes, &doc); err != nil {
		return fmt.Errorf("request body is not valid JSON: %w", err)
	}

	// Validate
	if err := schema.Validate(doc); err != nil {
		return fmt.Errorf("ASI04 payload schema violation for skill '%s': %w", contract.SkillName, err)
	}

	return nil
}
