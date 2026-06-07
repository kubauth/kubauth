/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package misc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// helpers --------------------------------------------------------------

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}
	return p
}

// tests ----------------------------------------------------------------

func TestLoadConfig_ParsesYAMLIntoStruct(t *testing.T) {
	type cfg struct {
		Name string `yaml:"name"`
		Port int    `yaml:"port"`
	}
	path := writeTempConfig(t, "name: kubauth\nport: 6801\n")
	var c cfg
	abs, err := LoadConfig(path, &c)
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}
	if !filepath.IsAbs(abs) {
		t.Errorf("returned path should be absolute, got %q", abs)
	}
	if c.Name != "kubauth" || c.Port != 6801 {
		t.Errorf("config not parsed: %+v", c)
	}
}

func TestLoadConfig_ExpandsEnvBeforeParsing(t *testing.T) {
	t.Setenv("KUBAUTH_TEST_NAME", "alice")
	type cfg struct {
		User string `yaml:"user"`
	}
	path := writeTempConfig(t, "user: ${KUBAUTH_TEST_NAME}\n")
	var c cfg
	if _, err := LoadConfig(path, &c); err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}
	if c.User != "alice" {
		t.Errorf("env var not expanded: %+v", c)
	}
}

func TestLoadConfig_MissingEnvVarSurfacesAsError(t *testing.T) {
	type cfg struct {
		User string `yaml:"user"`
	}
	path := writeTempConfig(t, "user: ${KUBAUTH_TEST_DOES_NOT_EXIST_8472}\n")
	var c cfg
	_, err := LoadConfig(path, &c)
	if err == nil {
		t.Fatal("expected MissingVariableError, got nil")
	}
	if !strings.Contains(err.Error(), "KUBAUTH_TEST_DOES_NOT_EXIST_8472") {
		t.Errorf("error should mention the missing var, got %q", err.Error())
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	type cfg struct{}
	abs, err := LoadConfig("/no/such/file/at/all/please.yaml", &cfg{})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !filepath.IsAbs(abs) {
		t.Errorf("returned path should still be absolute even on read error, got %q", abs)
	}
	if !os.IsNotExist(err) && !strings.Contains(err.Error(), "no such file") {
		t.Errorf("expected file-not-found, got %v", err)
	}
}

func TestLoadConfig_RejectsUnknownYAMLFields(t *testing.T) {
	// LoadConfig sets `decoder.SetStrict(true)` — unknown fields must error.
	// This protects against silent typos in production configs.
	type cfg struct {
		Name string `yaml:"name"`
	}
	path := writeTempConfig(t, "name: ok\nunknown_field: should_error\n")
	var c cfg
	_, err := LoadConfig(path, &c)
	if err == nil {
		t.Fatal("expected strict-mode error for unknown field")
	}
	if !strings.Contains(err.Error(), "unknown_field") {
		t.Errorf("error should mention the unknown field, got %q", err.Error())
	}
}

func TestLoadConfig_EmptyFileIsNotAnError(t *testing.T) {
	type cfg struct {
		Name string `yaml:"name"`
	}
	path := writeTempConfig(t, "")
	var c cfg
	if _, err := LoadConfig(path, &c); err != nil {
		t.Fatalf("empty file should not error, got %v", err)
	}
	if c.Name != "" {
		t.Errorf("empty file should leave struct zero-valued, got %+v", c)
	}
}

func TestLoadConfig_RelativePathBecomesAbsolute(t *testing.T) {
	type cfg struct {
		Name string `yaml:"name"`
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "rel.yaml")
	if err := os.WriteFile(path, []byte("name: ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Use a relative path by chdir'ing into the temp dir.
	cwd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	var c cfg
	abs, err := LoadConfig("rel.yaml", &c)
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}
	if !filepath.IsAbs(abs) {
		t.Errorf("expected absolute path back, got %q", abs)
	}
}
