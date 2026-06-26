#!/usr/bin/env bash
# Runs `go test -json ./...` and writes a vitest-compatible summary JSON so
# run-tests.sh can parse actual test counts instead of using the exit-code fallback.
# Usage: bash .claude/go-test-json.sh <report-file>
set -uo pipefail

report="${1:-.test-tmp/go.json}"
events=".test-tmp/go-events.jsonl"
mkdir -p "$(dirname "$report")" .test-tmp

go test -json ./... >"$events" 2>&1
code=$?

# Parse JSON event stream: count test-level pass/fail (lines with a Test field).
jq -s '
  [.[] | select(.Test != null)] as $tests |
  {
    numTotalTests:  ($tests | map(select(.Action == "pass" or .Action == "fail")) | length),
    numPassedTests: ($tests | map(select(.Action == "pass")) | length),
    numFailedTests: ($tests | map(select(.Action == "fail")) | length),
    testResults: [
      {
        name: "go",
        assertionResults: [
          $tests[] | select(.Action == "fail") |
          {
            status: "failed",
            title: .Test,
            ancestorTitles: [(.Package // "")]
          }
        ]
      }
    ]
  }
' "$events" > "$report" 2>/dev/null || \
  echo '{"numTotalTests":0,"numPassedTests":0,"numFailedTests":1,"testResults":[]}' > "$report"

exit $code
