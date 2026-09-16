## Fuzzy Testing in Go: A Comprehensive Guide

Fuzzy testing is a powerful technique for finding edge cases and bugs in your code by automatically generating random test inputs. Go's built-in fuzzing support, introduced in Go 1.18, makes it easy to write effective fuzzy tests without external dependencies.

## What Is Fuzzy Testing?

Fuzzy testing (or fuzz testing) is a form of property-based testing that feeds random, invalid, or unexpected inputs to your code to find crashes, memory leaks, or unhandled edge cases. Unlike traditional unit tests where you manually define inputs and expected outputs, fuzz tests let the Go runtime explore your code's behavior space automatically.

### Why Fuzzy Testing Matters

- **Discovers unexpected edge cases**: Your code may fail with inputs you never anticipated
- **Finds security vulnerabilities**: Malformed inputs can expose security flaws
- **Improves robustness**: Fuzzy tests exercise your code in ways manual testing often misses
- **Regression detection**: Failed fuzz inputs become permanent test cases
- **Minimal setup**: Go's fuzzing is built-in and requires no external frameworks

## Basic Fuzzing Syntax

A fuzz test in Go is a function with the signature:

```go
func FuzzFunctionName(f *testing.F) {
    // Test implementation
}
```

The key differences from standard tests:

1. Use `*testing.F` instead of `*testing.T`
2. Provide seed corpus values with `f.Add()`
3. Call `f.Fuzz()` with a callback function that receives random inputs
4. The fuzzing engine generates variations of your seed values

## Example 1: Fuzzing a JSON Parser

Let's start with a practical example: fuzzing a simple JSON parser.

```go
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
```

To run this fuzz test:

```bash
go test -fuzz=FuzzJSONParser ./parser
```

The fuzzing engine will explore variations like `{"name":"Alice","age":30}`, `{"name":"","age":0}`, `{"name":null}`, etc., automatically discovering edge cases.

## Example 2: Fuzzing a URL Parser

Here's a more complex example that fuzzes URL parsing:

```go
package urlparser

import (
    "net/url"
    "testing"
    "strings"
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
```

## Example 3: The Fuzzer Found a Bug in My Own Code

The previous two examples fuzzed the standard library, which is already fuzzed continuously upstream - the fuzzer found nothing, and that is the expected outcome. This example is different: the fuzzer found a genuine bug in code I wrote myself, within seconds.

A function that strips dangerous HTML before you render it is a prime fuzzing target. Bugs there are security bugs (XSS), the input space is effectively unlimited, and the things that must never survive are easy to express as properties. Here is the first version I wrote - one replacement pass for each kind of dangerous bit:

```go
// v1 - broken, do not copy: a single replacement pass per pattern
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
```

Reasonable looking, if over-optimistic. I wrapped it in a fuzz test that asserts four properties:

```go
func FuzzSanitizeHTML(f *testing.F) {
    // ...seed values...
    f.Fuzz(func(t *testing.T, input string) {
        result := SanitizeHTML(input)

        // Property 1: Result should not contain <script> tags
        if strings.Contains(strings.ToLower(result), "<script") {
            t.Errorf("Sanitized output contains script tag")
        }

        // Property 2: Result should not contain event handler attributes
        if strings.Contains(strings.ToLower(result), " onclick=") ||
            strings.Contains(strings.ToLower(result), " onerror=") ||
            strings.Contains(strings.ToLower(result), " onload=") {
            t.Errorf("Sanitized output contains event handler")
        }

        // Property 3: Should not panic on any input (implicit)
        // Property 4: Output length should not increase
        if len(result) > len(input) {
            t.Errorf("Sanitization increased length from %d to %d",
                len(input), len(result))
        }
    })
}
```

### What the fuzzer found

Within a few seconds the fuzzer reported a failing input I never would have thought of:

```
<<sCript>sCript
```

Tracing it, every pass worked individually and the output was still a script tag. `SanitizeHTML`'s second pass removes the `<sCript>` in the middle, which is replaced by the empty string. Removing that chunk makes two leftover fragments - the leading `<` and the trailing `sCript` - join back together into `<sCript`, which lowercases to `<script`. Because `ReplaceAllString` only makes a single pass over the input, the freshly joined tag is never re-examined, so it sails through into the output.

This is the general failure mode of any "remove dangerous bits" function that runs each pattern exactly once: the text you remove can act as glue between the fragments on either side of it. Your output can be fine at every intermediate step and still be wrong at the end.

### The fix: iterate to a fixpoint

The fix follows directly from the diagnosis: keep reapplying the removals until the output stops changing. Since every removal only shortens the string, the loop is guaranteed to terminate.

```go
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
```

With that change, `<<sCript>sCript` is scrubbed to empty and a fresh fuzz run stays green for millions of executions. The fix also introduces a `\b` word boundary in the event-handler regex, and the same boundary appears in the script-tag check further down - both of which come out of reviewing the properties, next.

### Hardening the properties

Fixing the specific failing input was satisfying, but the fuzzer is only as good as the properties it checks. I re-read my own assertions and found two gaps:

- **Property 1 only looked for `"<script"` literally.** A fragment like `<<sCript` lowercases into the check string by accident, and a stray `</script>` closing tag was not caught at all. I want to assert "no script tag, in any casing or fragment form", so the pattern became `(?i)</?script\b` - the optional `/` covers closing tags, and the word boundary keeps it from matching innocent words like `scripty`.
- **Property 2 only checked `onclick`, `onerror`, and `onload`.** The sanitizer claims to remove *any* `on*` attribute, so the property should check all of them: `(?i)\bon\w+\s*=`. The `\b` again is deliberate - it means `cotton=` and `wagon=` are untouched, which I added as seed values to keep the sanitizer honest.

The `\b` in the sanitizer's `eventRe` was added so the sanitizer and the stronger property agree. The resulting file, with both properties in their hardened form, is:

```go
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
```

The stronger properties are also what let the fuzzer exercise the hard cases: once `eventAttrRe` started checking every `on*` attribute, a second class of bug surfaced - a handler smuggled *inside the value* of another handler. Removing `onclick=` from `<div onclick='onload=1'>` leaves the value's own `onload=` exposed; the fixpoint loop scrubs that too, because it reapplies `eventRe` until nothing matches.

### What the properties still do not catch

The fuzzer found one real bug and the hardened properties ruled out an entire class of joins. But an honest section on fuzzing a sanitizer has to end with its limits: **a fuzz test verifies exactly the properties you write, nothing more.** This sanitizer never promises to strip `javascript:` links, `<style>`-based attacks, or `<iframe>` embeds, and fuzzing would happily confirm that all of them sail through - because no property asserts otherwise. Properties 1 and 2 only guard what `SanitizeHTML` claims to remove.

That is the real lesson. Property-based fuzzing is the tool to pick when you can say *"here is what must always be true"* - and writing those assertions forces you to decide, up front, what your code actually promises. For production XSS protection I would not iterate on regexes at all; I would tokenize with Go's `html` package or use a maintained sanitizer library, and add properties for `javascript:` URLs on top. But as a demonstration of how a few seconds of fuzzing can surface a bug in code you were sure was fine, this one is hard to beat.

## Example 4: Fuzzing a Math Function

Let's fuzz a function that performs math operations:

```go
package math_utils

import (
    "errors"
    "math"
    "testing"
)

// SafeDiv performs division with safety checks
func SafeDiv(a, b float64) (float64, error) {
    if math.IsNaN(a) || math.IsNaN(b) {
        return 0, ErrNaN
    }
    if b == 0 {
        return 0, ErrDivisionByZero
    }
    result := a / b
    // A true quotient that exceeds float64's range is reported as an error
    // rather than silently returning +Inf/-Inf.
    if math.IsNaN(result) || math.IsInf(result, 0) {
        return 0, ErrOverflow
    }
    return result, nil
}

var (
    ErrDivisionByZero = &DivError{"division by zero"}
    ErrNaN            = &DivError{"NaN value"}
    ErrOverflow       = &DivError{"overflow"}
)

type DivError struct {
    msg string
}

func (e *DivError) Error() string { return e.msg }

func FuzzSafeDiv(f *testing.F) {
    f.Add(10.0, 2.0)
    f.Add(-5.0, 2.0)
    f.Add(0.0, 1.0)
    f.Add(1e308, 2.0)

    f.Fuzz(func(t *testing.T, a, b float64) {
        result, err := SafeDiv(a, b)

        // If b is zero, should error
        if b == 0 {
            if err == nil {
                t.Errorf("Expected error for division by zero, got result: %v", result)
            }
            return
        }

        // If either is NaN, should error
        if math.IsNaN(a) || math.IsNaN(b) {
            if err == nil {
                t.Errorf("Expected error for NaN, got result: %v", result)
            }
            return
        }

        // A genuine overflow (true quotient out of float64 range) is a
        // legitimate error - not a bug.
        if errors.Is(err, ErrOverflow) {
            return
        }

        // Otherwise should succeed
        if err != nil {
            t.Errorf("Unexpected error: %v", err)
            return
        }

        // Result should be finite
        if math.IsNaN(result) || math.IsInf(result, 0) {
            t.Errorf("Result is not finite: %v", result)
        }

        // Verify correctness: a/b * b ≈ a (allowing for floating point error)
        reconstructed := result * b
        if !floatsAlmostEqual(reconstructed, a, 1e-10) {
            t.Errorf("Math verification failed: %v / %v = %v, but %v * %v = %v",
                a, b, result, result, b, reconstructed)
        }
    })
}

// floatsAlmostEqual compares using relative error, which is correct for
// floating point values that span many orders of magnitude.
func floatsAlmostEqual(a, b, relEpsilon float64) bool {
    diff := math.Abs(a - b)
    denominator := math.Max(math.Abs(a), math.Abs(b))
    if denominator == 0 {
        return diff < relEpsilon
    }
    return diff/denominator < relEpsilon
}
```

## Example 5: Fuzzing with Byte Slices

Some functions need to work with binary data. Here's how to fuzz those:

```go
package decompression

import (
    "bytes"
    "compress/gzip"
    "io"
    "testing"
)

// CompressData compresses bytes using gzip
func CompressData(data []byte) ([]byte, error) {
    var buf bytes.Buffer
    w := gzip.NewWriter(&buf)
    if _, err := w.Write(data); err != nil {
        return nil, err
    }
    w.Close()
    return buf.Bytes(), nil
}

// DecompressData decompresses gzip data
func DecompressData(compressed []byte) ([]byte, error) {
    r, err := gzip.NewReader(bytes.NewReader(compressed))
    if err != nil {
        return nil, err
    }
    defer r.Close()
    return io.ReadAll(r)
}

func FuzzCompressionRoundtrip(f *testing.F) {
    f.Add([]byte("Hello, World!"))
    f.Add([]byte(""))
    f.Add([]byte("The quick brown fox jumps over the lazy dog"))
    f.Add([]byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD})

    f.Fuzz(func(t *testing.T, original []byte) {
        // Compress the data
        compressed, err := CompressData(original)
        if err != nil {
            t.Fatalf("Compression failed: %v", err)
        }

        // Decompress it
        decompressed, err := DecompressData(compressed)
        if err != nil {
            t.Fatalf("Decompression failed: %v", err)
        }

        // Verify we get the original back
        if !bytes.Equal(original, decompressed) {
            t.Errorf("Round-trip failed:\nOriginal:     %v\nDecompressed: %v",
                original, decompressed)
        }
    })
}

// Fuzz malformed gzip data
func FuzzMalformedGzip(f *testing.F) {
    f.Add([]byte{0x1F, 0x8B}) // Incomplete gzip header
    f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})
    f.Add([]byte{})

    f.Fuzz(func(t *testing.T, data []byte) {
        _, err := DecompressData(data)
        // We don't care if it errors - just that it doesn't panic
        _ = err
    })
}
```

## Running and Managing Fuzz Tests

`go test -fuzz` accepts exactly **one fuzz test, in one package, per run** - it fuzzes a single target until it finds a failure or the time budget is up. If `-fuzz` matches more than one fuzz test (as `-fuzz=.` does in a package with several), `go test` refuses to run:

```
$ go test -fuzz=. ./decompression
testing: will not fuzz, -fuzz matches more than one fuzz test:
[FuzzCompressionRoundtrip FuzzMalformedGzip]
```

### Run everything: regular tests plus every fuzz target
`go test ./...` runs the seed corpus of every fuzz test as ordinary tests, but it does not actually fuzz anything. To fuzz, each target must be invoked on its own. The `scripts/run-all-tests.sh` script does both - it builds, vets, runs the seed corpus, then fuzzes every target across every package:

```bash
./scripts/run-all-tests.sh
```

Fuzzing runs forever by default, so the script gives each target a time budget controlled by the `FUZZTIME` environment variable (default `30s`):

```bash
FUZZTIME=10s ./scripts/run-all-tests.sh   # shorter run, CI-friendly
```

The broken version of the sanitizer from Example 3 ships in its own package, `sanitizer_with_bug`, to demonstrate the failure. Its test fails by design, so the script records the failures and continues with the remaining packages and targets, instead of aborting; the run still reports a green exit as long as the only failures come from that deliberately broken package.

### Run a single fuzz test:
```bash
go test -fuzz=FuzzJSONParser ./parser
```

### Run every fuzz test in a package:
Name each target on its own. You can enumerate them first with `-list`:

```bash
go test -list '^Fuzz' ./decompression
# FuzzCompressionRoundtrip
# FuzzMalformedGzip

go test -fuzz=FuzzCompressionRoundtrip ./decompression
go test -fuzz=FuzzMalformedGzip ./decompression
```

or loop over them in one command (filtering out the `ok` summary line):

```bash
for test in $(go test -list '^Fuzz' ./decompression | grep '^Fuzz'); do
    go test -fuzz="^$test$" ./decompression
done
```

### Run for a specific duration:
```bash
go test -fuzz=FuzzJSONParser -fuzztime=30s ./parser
```

### Run with specific CPU count:
```bash
go test -fuzz=FuzzJSONParser -fuzztime=1m -parallel=4 ./parser
```

## Understanding Fuzz Test Results

When the fuzzing engine finds a failing input, it saves it to a corpus file like:

```
testdata/fuzz/FuzzFunctionName/[corpus-id]
```

These corpus entries become permanent test cases that are checked on every test run, ensuring regressions don't occur.

## Best Practices

1. **Use properties, not assertions**: Test properties that should always be true rather than specific outputs
2. **Keep fuzz functions fast**: Simpler functions fuzz better
3. **Provide good seed values**: Good seeds help the fuzzer explore more effectively
4. **Test error paths**: Make sure your code handles invalid input gracefully
5. **Avoid flaky checks**: Don't rely on timing or randomness in assertions
6. **Use constraints from inside the callback**: Call `t.Skip()` on invalid input combinations early. The argument to `f.Fuzz` is a regular test callback, so it receives `*testing.T` - use its methods. Calling an `*F` method there is an error: Go 1.25 and later refuse to build it, and earlier versions panic at run time with `testing: f.Skip was called inside the fuzz target, use t.Skip instead`.
7. **Monitor performance**: Profiling can reveal performance issues the fuzzer discovers

## Conclusion

Fuzzy testing in Go is a first-class feature that helps you write more robust code. By combining seed corpus values with automated input generation, you can discover edge cases and vulnerabilities that traditional testing might miss. Start with simple properties and gradually add more sophisticated tests—Go's fuzzing engine will do the heavy lifting of finding bugs.

Whether you're building parsers, sanitizers, mathematical functions, or data processors, fuzzing should be part of your testing strategy.
