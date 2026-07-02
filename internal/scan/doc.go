// Package scan implements the secret detection engine used by the cifra
// pre-commit hook and the `cifra scan` CLI command.
// It provides pattern-based rules and a Shannon-entropy heuristic for finding
// plaintext credentials in unified diffs and tracked file trees.
package scan
