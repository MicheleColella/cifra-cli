package git

import (
	"os"
	"path/filepath"
	"testing"
)

func writeGitConfig(t *testing.T, root, content string) {
	t.Helper()
	gitDir := filepath.Join(root, ".git")
	if err := os.MkdirAll(gitDir, 0o700); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "config"), []byte(content), 0o600); err != nil {
		t.Fatalf("write .git/config: %v", err)
	}
}

func TestDetectOrigin(t *testing.T) {
	dir := t.TempDir()
	writeGitConfig(t, dir, `[core]
	repositoryformatversion = 0
	filemode = true
[remote "origin"]
	url = https://github.com/example/repo.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
`)

	got, err := DetectOrigin(dir)
	if err != nil {
		t.Fatalf("DetectOrigin: %v", err)
	}
	if got != "https://github.com/example/repo.git" {
		t.Errorf("got %q, want https://github.com/example/repo.git", got)
	}
}

func TestDetectOrigin_SSHRemote(t *testing.T) {
	dir := t.TempDir()
	writeGitConfig(t, dir, `[remote "origin"]
	url = git@github.com:example/repo.git
`)

	got, err := DetectOrigin(dir)
	if err != nil {
		t.Fatalf("DetectOrigin: %v", err)
	}
	if got != "git@github.com:example/repo.git" {
		t.Errorf("got %q, want git@github.com:example/repo.git", got)
	}
}

func TestDetectOrigin_NoGitDir(t *testing.T) {
	dir := t.TempDir()
	got, err := DetectOrigin(dir)
	if err != nil {
		t.Fatalf("DetectOrigin: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestDetectOrigin_NoOriginRemote(t *testing.T) {
	dir := t.TempDir()
	writeGitConfig(t, dir, `[core]
	repositoryformatversion = 0
[remote "upstream"]
	url = https://github.com/other/repo.git
`)

	got, err := DetectOrigin(dir)
	if err != nil {
		t.Fatalf("DetectOrigin: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestDetectOrigin_MultipleRemotes(t *testing.T) {
	dir := t.TempDir()
	writeGitConfig(t, dir, `[remote "upstream"]
	url = https://github.com/other/repo.git
[remote "origin"]
	url = https://github.com/mine/repo.git
`)

	got, err := DetectOrigin(dir)
	if err != nil {
		t.Fatalf("DetectOrigin: %v", err)
	}
	if got != "https://github.com/mine/repo.git" {
		t.Errorf("got %q, want https://github.com/mine/repo.git", got)
	}
}
