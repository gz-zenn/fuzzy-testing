package parser

import (
	"encoding/json"
	"testing"
)

func FuzzJSONParser(f *testing.F) {
	// Add seed corpus values
	f.Add(`{"name":"Alice","age":30}`)
	f.Add(`{"items":[1,2,3]}`)
	f.Add(`{"nested":{"key":"value"}}`)
	f.Add(`[]`)
	f.Add(`null`)

	f.Fuzz(func(t *testing.T, input string) {
		var result interface{}

		// Try to unmarshal the JSON
		err := json.Unmarshal([]byte(input), &result)

		// If it doesn't error, verify we can marshal it back
		if err == nil {
			data, marshalErr := json.Marshal(result)
			if marshalErr != nil {
				t.Errorf("Failed to marshal valid JSON: %v", marshalErr)
			}

			// Verify it's still valid JSON
			var result2 interface{}
			if err := json.Unmarshal(data, &result2); err != nil {
				t.Errorf("Re-unmarshaling failed: %v", err)
			}
		}
	})
}
