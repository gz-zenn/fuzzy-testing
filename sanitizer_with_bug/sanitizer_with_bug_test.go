package sanitizer_with_bug

import (
	"regexp"
	"strings"
	"testing"
)

// SanitizeHTML is the v1 implementation from the README's Example 3 - broken,
// do not copy. Each regex runs exactly one replacement pass, so whatever text
// gets removed can act as glue between the fragments on either side of it,
// joining them into a brand new tag. One pass turns "<<sCript>sCript" into
// "<sCript", which lowercases to a fresh "<script". See ./sanitizer for the
// fixed version that iterates to a fixpoint.
func SanitizeHTML(input string) string {
	// Remove complete script blocks (opening tag, content, closing tag)
	scriptRe := regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	output := scriptRe.ReplaceAllString(input, "")

	// Remove any remaining unclosed opening <script tags
	openRe := regexp.MustCompile(`(?i)<script[^>]*>?`)
	output = openRe.ReplaceAllString(output, "")

	// Remove event handlers
	eventRe := regexp.MustCompile(`(?i)\s+on\w+\s*=`)
	output = eventRe.ReplaceAllString(output, " ")

	return output
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
	// The input the fuzzer found: every pass works on its own, but together
	// the removals leave a freshly joined "<sCript" behind. Kept as a seed so
	// the bug reproduces on the first run - no fuzzing required.
	f.Add("<<sCript>sCript")

	f.Fuzz(func(t *testing.T, input string) {
		result := SanitizeHTML(input)

		// Property 1: Result should not contain <script> tags
		if strings.Contains(strings.ToLower(result), "<script") {
			t.Errorf("Sanitized output contains script tag: %q", result)
		}

		// Property 2: Result should not contain event handler attributes
		if strings.Contains(strings.ToLower(result), " onclick=") ||
			strings.Contains(strings.ToLower(result), " onerror=") ||
			strings.Contains(strings.ToLower(result), " onload=") {
			t.Errorf("Sanitized output contains event handler: %q", result)
		}

		// Property 3: Should not panic on any input (implicit)

		// Property 4: Output length should not increase
		if len(result) > len(input) {
			t.Errorf("Sanitization increased length from %d to %d",
				len(input), len(result))
		}
	})
}