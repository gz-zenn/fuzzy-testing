package urlparser

import (
	"net/url"
	"strings"
	"testing"
)

func FuzzURLParser(f *testing.F) {
	// Seed with valid URLs
	f.Add("https://example.com/path?query=value")
	f.Add("http://localhost:8080")
	f.Add("ftp://user:pass@host.com/file.txt")
	f.Add("mailto:user@example.com")
	f.Add("//example.com/path")

	f.Fuzz(func(t *testing.T, input string) {
		u, err := url.Parse(input)

		// Not all strings are valid URLs - that's fine.
		if err != nil {
			return
		}

		// A successfully parsed URL must be round-trippable: parsing its
		// serialized form again must yield the same URL. This catches
		// inconsistencies in how components are encoded/decoded.
		u2, err2 := url.Parse(u.String())
		if err2 != nil {
			t.Errorf("Re-parsing %q failed: %v", u.String(), err2)
			return
		}
		if u2.String() != u.String() {
			t.Errorf("Round-trip mismatch: %q != %q", u2.String(), u.String())
		}

		// If a scheme was recognized, the original input must contain it.
		// Go normalizes scheme names to lowercase.
		if u.Scheme != "" && !strings.Contains(strings.ToLower(input), u.Scheme+":") {
			t.Errorf("Scheme %q not present in input %q", u.Scheme, input)
		}
	})
}
