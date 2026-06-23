package git

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// DetectOrigin reads the URL of the "origin" remote by parsing .git/config
// inside repoRoot directly — no git binary required.
// Returns an empty string when the file is absent or no origin is configured.
func DetectOrigin(repoRoot string) (string, error) {
	f, err := os.Open(filepath.Join(repoRoot, ".git", "config"))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()

	var inOrigin bool
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			inOrigin = line == `[remote "origin"]`
			continue
		}
		if inOrigin {
			k, v, ok := strings.Cut(line, "=")
			if ok && strings.TrimSpace(k) == "url" {
				return strings.TrimSpace(v), nil
			}
		}
	}
	return "", sc.Err()
}
