package sanitizer

import (
	"regexp"
	"testing"
)

// scriptTagRe matches any script tag or fragment of one, in any casing: an
// opening tag `<script ...>`, a closing tag `</script>`, or leftover
// fragments that could rejoin into either. The word boundary keeps it from
// matching innocent words like "scripty".
var scriptTagRe = regexp.MustCompile(`(?i)</?script\b`)

// eventAttrRe matches any event-handler attribute such as onclick=, onerror=,
// onload=. A word boundary means only attribute positions count - "cotton="
// or "wagon=" are untouched.
var eventAttrRe = regexp.MustCompile(`(?i)\bon\w+\s*=`)

// SanitizeHTML removes script tags and event handlers from input.
//
// The removals are repeated until the output stops changing. A single
// replacement pass is not enough: whatever text gets removed between two
// leftover fragments can act as the glue that joins those fragments into a
// brand new tag. For example, one pass turns "<<sCript>sCript" into
// "<sCript" (the "<" and "sCript" fragments rejoin into a script tag).
// Iterating to a fixpoint starves the fragments of any glue to rejoin with.
func SanitizeHTML(input string) string {
	// Remove complete script blocks (opening tag, content, closing tag)
	scriptBlockRe := regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	// Remove any remaining unclosed or unmatched <script>/</script> tags
	scriptOpenRe := regexp.MustCompile(`(?i)</?script[^>]*>?`)
	// Remove event handlers
	eventRe := regexp.MustCompile(`(?i)\bon\w+\s*=`)

	output := input
	for {
		before := output
		output = scriptBlockRe.ReplaceAllString(output, "")
		output = scriptOpenRe.ReplaceAllString(output, "")
		output = eventRe.ReplaceAllString(output, " ")
		if output == before {
			return output
		}
	}
}

func FuzzSanitizeHTML(f *testing.F) {
	f.Add("<p>Hello World</p>")
	f.Add("<script>alert('xss')</script><p>Safe</p>")
	f.Add("<img src='x' onerror='alert(1)'>")
	f.Add("<div onclick='bad()'>Click me</div>")
	f.Add("<img src='x' onmouseover='bad()'>")
	f.Add("<div onclick='x' onload='x'>")
	f.Add("")
	f.Add("Plain text")
	f.Add("cotton=wagon") // words containing "on" should not be stripped

	f.Fuzz(func(t *testing.T, input string) {
		result := SanitizeHTML(input)

		// Property 1: Result should not contain script tags, closing tags,
		// or fragments of them (case-insensitive).
		if scriptTagRe.MatchString(result) {
			t.Errorf("Sanitized output contains script tag: %q", result)
		}

		// Property 2: Result should not contain event-handler attributes.
		// Any on* attribute is treated as a handler - not just the ones the
		// sanitizer claims to remove.
		if eventAttrRe.MatchString(result) {
			t.Errorf("Sanitized output contains event handler: %q", result)
		}

		// Property 3: Should not panic on any input
		// (This is implicit - if it panics, the test fails)

		// Property 4: Length should not increase
		if len(result) > len(input) {
			t.Errorf("Sanitization increased length from %d to %d",
				len(input), len(result))
		}
	})
}
