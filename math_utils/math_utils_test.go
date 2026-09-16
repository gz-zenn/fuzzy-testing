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
