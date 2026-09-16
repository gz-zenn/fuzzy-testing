#!/usr/bin/env bash
# Run the full suite: build, vet, seed corpora, then every fuzz target.
#
# Example 3 ships two versions of the sanitizer on purpose:
#   - ./sanitizer      the fixed version (iterates to a fixpoint)
#   - ./sanitizer_with_bug   the broken sanitizer from the README, kept as a demo
# The broken version's test fails by design (it seeds the exact input the
# fuzzer found), so a failing test or fuzz target must NOT abort the run.
# Failures are collected, printed as a summary, and the script exits 0 as
# long as every failure is listed in KNOWN_FAILING_TARGETS.
set -uo pipefail

# How long to fuzz each target. Fuzzing runs forever by default, so bound it.
FUZZTIME="${FUZZTIME:-30s}"

# Packages whose tests/fuzz targets are intentionally broken. Their failures
# are expected and do not fail the script.
KNOWN_FAILING_TARGETS=(
	"sanitizer_with_bug"
)

cd "$(dirname "$0")/.."

failures=()

record_failure() {
	failures+=("$1")
}

is_expected_failure() {
	local name="$1"
	for known in "${KNOWN_FAILING_TARGETS[@]}"; do
		if [[ "$name" == *"$known"* ]]; then
			return 0
		fi
	done
	return 1
}

echo "==> go build ./..."
go build ./... || { echo "BUILD FAILED"; exit 1; }

echo "==> go vet ./..."
go vet ./... || { echo "VET FAILED"; exit 1; }

echo "==> go test ./... (seed corpus)"
for pkg in $(go list ./...); do
	echo "--> go test $pkg"
	if ! go test "$pkg"; then
		record_failure "$pkg (seed corpus)"
	fi
done

# Run every fuzz target, one per package, one at a time. -fuzz only accepts
# a single target per run, so -fuzz=. fails in packages with several
# (e.g. ./decompression).
for pkg in $(go list ./...); do
	for target in $(go test -list '^Fuzz' "$pkg" | grep '^Fuzz'); do
		echo "==> go test -fuzz=^${target}$ -fuzztime=${FUZZTIME} $pkg"
		if ! go test -fuzz="^${target}$" -fuzztime="${FUZZTIME}" "$pkg"; then
			record_failure "$pkg ($target, fuzz)"
		fi
	done
done

if [[ ${#failures[@]} -gt 0 ]]; then
	echo
	echo "=============================="
	echo "Failures (run continued):"
	expected_count=0
	for fault in "${failures[@]}"; do
		if is_expected_failure "$fault"; then
			echo "  [expected] $fault"
			expected_count=$((expected_count + 1))
		else
			echo "  [UNEXPECTED] $fault"
		fi
	done
	echo "=============================="
	if [[ $expected_count -eq ${#failures[@]} ]]; then
		echo "All failures were expected (broken =${KNOWN_FAILING_TARGETS[*]} demo)."
		exit 0
	fi
	echo "Unexpected failures present - see above."
	exit 1
fi

echo
echo "All tests passed."