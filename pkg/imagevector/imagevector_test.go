// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package imagevector_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gardener/oidc-apps-controller/pkg/imagevector"
)

const testImagesYAML = `
images:
  - name: test-image
    sourceRepository: github.com/test/test-image
    repository: example.com/test-image
    tag: "v1.0.0"
  - name: another-image
    repository: example.com/another-image
    tag: "v2.0.0"
`

func TestRead(t *testing.T) {
	vec, err := imagevector.Read([]byte(testImagesYAML))
	if err != nil {
		t.Fatalf("Failed to read image vector: %v", err)
	}

	// Test finding an image
	img, err := vec.FindImage("test-image")
	if err != nil {
		t.Fatalf("Failed to find test-image: %v", err)
	}

	if img.Name != "test-image" {
		t.Errorf("Expected image name 'test-image', got '%s'", img.Name)
	}

	if img.Repository != "example.com/test-image" {
		t.Errorf("Expected repository 'example.com/test-image', got '%s'", img.Repository)
	}

	if img.Tag != "v1.0.0" {
		t.Errorf("Expected tag 'v1.0.0', got '%s'", img.Tag)
	}

	if img.String() != "example.com/test-image:v1.0.0" {
		t.Errorf("Expected String() to return 'example.com/test-image:v1.0.0', got '%s'", img.String())
	}

	// Test finding non-existent image
	_, err = vec.FindImage("non-existent")
	if err == nil {
		t.Error("Expected error when finding non-existent image")
	}
}

func TestWithEnvOverride(t *testing.T) {
	// Write a temporary override file
	overrideYAML := `
images:
  - name: test-image
    repository: override.com/test-image
    tag: "v3.0.0"
`

	overrideFile := filepath.Join(t.TempDir(), "override.yaml")
	if err := os.WriteFile(overrideFile, []byte(overrideYAML), 0600); err != nil {
		t.Fatalf("Failed to write override file: %v", err)
	}

	t.Setenv("IMAGEVECTOR_OVERWRITE", overrideFile)

	vec, err := imagevector.Read([]byte(testImagesYAML))
	if err != nil {
		t.Fatalf("Failed to read image vector: %v", err)
	}

	// Apply environment overrides
	overriddenVec, err := imagevector.WithEnvOverride(vec, imagevector.OverrideEnv)
	if err != nil {
		t.Fatalf("Failed to apply environment overrides: %v", err)
	}

	// Test overridden image
	img, err := overriddenVec.FindImage("test-image")
	if err != nil {
		t.Fatalf("Failed to find test-image: %v", err)
	}

	if img.Repository != "override.com/test-image" {
		t.Errorf("Expected overridden repository 'override.com/test-image', got '%s'", img.Repository)
	}

	if img.Tag != "v3.0.0" {
		t.Errorf("Expected overridden tag 'v3.0.0', got '%s'", img.Tag)
	}

	// Test non-overridden image
	img2, err := overriddenVec.FindImage("another-image")
	if err != nil {
		t.Fatalf("Failed to find another-image: %v", err)
	}

	if img2.Repository != "example.com/another-image" {
		t.Errorf("Expected original repository 'example.com/another-image', got '%s'", img2.Repository)
	}

	if img2.Tag != "v2.0.0" {
		t.Errorf("Expected original tag 'v2.0.0', got '%s'", img2.Tag)
	}
}

func TestWithEnvOverrideEmptyEnv(t *testing.T) {
	vec, err := imagevector.Read([]byte(testImagesYAML))
	if err != nil {
		t.Fatalf("Failed to read image vector: %v", err)
	}

	// Env var is not set — should return original vector unchanged
	overriddenVec, err := imagevector.WithEnvOverride(vec, imagevector.OverrideEnv)
	if err != nil {
		t.Fatalf("Expected no error when env var is unset, got: %v", err)
	}

	img, err := overriddenVec.FindImage("test-image")
	if err != nil {
		t.Fatalf("Failed to find test-image: %v", err)
	}

	if img.Repository != "example.com/test-image" {
		t.Errorf("Expected original repository 'example.com/test-image', got '%s'", img.Repository)
	}
}

func TestWithEnvOverrideMissingFile(t *testing.T) {
	t.Setenv("IMAGEVECTOR_OVERWRITE", "/nonexistent/path/override.yaml")

	vec, err := imagevector.Read([]byte(testImagesYAML))
	if err != nil {
		t.Fatalf("Failed to read image vector: %v", err)
	}

	_, err = imagevector.WithEnvOverride(vec, imagevector.OverrideEnv)
	if err == nil {
		t.Error("Expected error when override file does not exist")
	}
}

func TestMergePartialOverride(t *testing.T) {
	// Override only the tag, repository should remain from base
	overrideYAML := `
images:
  - name: test-image
    tag: "v5.0.0"
`

	base, err := imagevector.Read([]byte(testImagesYAML))
	if err != nil {
		t.Fatalf("Failed to read base image vector: %v", err)
	}

	override, err := imagevector.Read([]byte(overrideYAML))
	if err != nil {
		t.Fatalf("Failed to read override image vector: %v", err)
	}

	merged := imagevector.Merge(base, override)

	img, err := merged.FindImage("test-image")
	if err != nil {
		t.Fatalf("Failed to find test-image: %v", err)
	}

	if img.Repository != "example.com/test-image" {
		t.Errorf("Expected original repository 'example.com/test-image', got '%s'", img.Repository)
	}

	if img.Tag != "v5.0.0" {
		t.Errorf("Expected overridden tag 'v5.0.0', got '%s'", img.Tag)
	}
}

func TestMergeNewImage(t *testing.T) {
	// Override file adds a new image not in the base
	overrideYAML := `
images:
  - name: new-image
    repository: example.com/new-image
    tag: "v1.0.0"
`

	base, err := imagevector.Read([]byte(testImagesYAML))
	if err != nil {
		t.Fatalf("Failed to read base image vector: %v", err)
	}

	override, err := imagevector.Read([]byte(overrideYAML))
	if err != nil {
		t.Fatalf("Failed to read override image vector: %v", err)
	}

	merged := imagevector.Merge(base, override)

	img, err := merged.FindImage("new-image")
	if err != nil {
		t.Fatalf("Failed to find new-image: %v", err)
	}

	if img.Repository != "example.com/new-image" {
		t.Errorf("Expected repository 'example.com/new-image', got '%s'", img.Repository)
	}
}

func TestReadInvalidYAML(t *testing.T) {
	_, err := imagevector.Read([]byte("invalid yaml: ["))
	if err == nil {
		t.Error("Expected error when reading invalid YAML")
	}
}

func TestReadEmptyImageName(t *testing.T) {
	invalidYAML := `
images:
  - name: ""
    repository: example.com/test
    tag: "v1.0.0"
`

	_, err := imagevector.Read([]byte(invalidYAML))
	if err == nil {
		t.Error("Expected error when image name is empty")
	}
}

func TestReadJSON(t *testing.T) {
	jsonData := `{"images":[{"name":"json-image","repository":"example.com/json-image","tag":"v1.0.0"}]}`

	vec, err := imagevector.Read([]byte(jsonData))
	if err != nil {
		t.Fatalf("Failed to read JSON image vector: %v", err)
	}

	img, err := vec.FindImage("json-image")
	if err != nil {
		t.Fatalf("Failed to find json-image: %v", err)
	}

	if img.Repository != "example.com/json-image" {
		t.Errorf("Expected repository 'example.com/json-image', got '%s'", img.Repository)
	}

	if img.Tag != "v1.0.0" {
		t.Errorf("Expected tag 'v1.0.0', got '%s'", img.Tag)
	}
}

func TestReadEmptyData(t *testing.T) {
	vec, err := imagevector.Read([]byte(""))
	if err != nil {
		t.Fatalf("Unexpected error reading empty data: %v", err)
	}

	_, err = vec.FindImage("anything")
	if err == nil {
		t.Error("Expected error finding image in empty vector")
	}
}

func TestReadFile(t *testing.T) {
	yamlData := `
images:
  - name: file-image
    repository: example.com/file-image
    tag: "v2.0.0"
`

	filePath := filepath.Join(t.TempDir(), "images.yaml")
	if err := os.WriteFile(filePath, []byte(yamlData), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	vec, err := imagevector.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	img, err := vec.FindImage("file-image")
	if err != nil {
		t.Fatalf("Failed to find file-image: %v", err)
	}

	if img.Repository != "example.com/file-image" {
		t.Errorf("Expected repository 'example.com/file-image', got '%s'", img.Repository)
	}

	if img.Tag != "v2.0.0" {
		t.Errorf("Expected tag 'v2.0.0', got '%s'", img.Tag)
	}
}

func TestReadFileNotFound(t *testing.T) {
	_, err := imagevector.ReadFile("/nonexistent/path/images.yaml")
	if err == nil {
		t.Error("Expected error when reading nonexistent file")
	}
}

func TestImageStringWithoutTag(t *testing.T) {
	img := &imagevector.Image{
		Name:       "test",
		Repository: "example.com/test",
	}

	if img.String() != "example.com/test" {
		t.Errorf("Expected 'example.com/test', got '%s'", img.String())
	}
}

func TestImageStringWithTag(t *testing.T) {
	img := &imagevector.Image{
		Name:       "test",
		Repository: "example.com/test",
		Tag:        "v1.0.0",
	}

	if img.String() != "example.com/test:v1.0.0" {
		t.Errorf("Expected 'example.com/test:v1.0.0', got '%s'", img.String())
	}
}

func TestImageStringWithSHA256Tag(t *testing.T) {
	img := &imagevector.Image{
		Name:       "test",
		Repository: "example.com/test",
		Tag:        "sha256:abc123def456",
	}

	expected := "example.com/test@sha256:abc123def456"
	if img.String() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, img.String())
	}
}

func TestMergeRepositoryOnlyOverride(t *testing.T) {
	// Override only the repository, tag should remain from base
	overrideYAML := `
images:
  - name: test-image
    repository: override.com/test-image
`

	base, err := imagevector.Read([]byte(testImagesYAML))
	if err != nil {
		t.Fatalf("Failed to read base image vector: %v", err)
	}

	override, err := imagevector.Read([]byte(overrideYAML))
	if err != nil {
		t.Fatalf("Failed to read override image vector: %v", err)
	}

	merged := imagevector.Merge(base, override)

	img, err := merged.FindImage("test-image")
	if err != nil {
		t.Fatalf("Failed to find test-image: %v", err)
	}

	if img.Repository != "override.com/test-image" {
		t.Errorf("Expected overridden repository 'override.com/test-image', got '%s'", img.Repository)
	}

	if img.Tag != "v1.0.0" {
		t.Errorf("Expected original tag 'v1.0.0', got '%s'", img.Tag)
	}
}

func TestMergeFullOverride(t *testing.T) {
	overrideYAML := `
images:
  - name: test-image
    repository: override.com/test-image
    tag: "v9.0.0"
`

	base, err := imagevector.Read([]byte(testImagesYAML))
	if err != nil {
		t.Fatalf("Failed to read base image vector: %v", err)
	}

	override, err := imagevector.Read([]byte(overrideYAML))
	if err != nil {
		t.Fatalf("Failed to read override image vector: %v", err)
	}

	merged := imagevector.Merge(base, override)

	img, err := merged.FindImage("test-image")
	if err != nil {
		t.Fatalf("Failed to find test-image: %v", err)
	}

	if img.Repository != "override.com/test-image" {
		t.Errorf("Expected overridden repository 'override.com/test-image', got '%s'", img.Repository)
	}

	if img.Tag != "v9.0.0" {
		t.Errorf("Expected overridden tag 'v9.0.0', got '%s'", img.Tag)
	}
}

func TestMergeSourceRepositoryOverride(t *testing.T) {
	overrideYAML := `
images:
  - name: test-image
    sourceRepository: github.com/override/test-image
`

	base, err := imagevector.Read([]byte(testImagesYAML))
	if err != nil {
		t.Fatalf("Failed to read base image vector: %v", err)
	}

	override, err := imagevector.Read([]byte(overrideYAML))
	if err != nil {
		t.Fatalf("Failed to read override image vector: %v", err)
	}

	merged := imagevector.Merge(base, override)

	img, err := merged.FindImage("test-image")
	if err != nil {
		t.Fatalf("Failed to find test-image: %v", err)
	}

	if img.SourceRepository != "github.com/override/test-image" {
		t.Errorf("Expected overridden sourceRepository 'github.com/override/test-image', got '%s'", img.SourceRepository)
	}

	// Repository and tag should remain from base
	if img.Repository != "example.com/test-image" {
		t.Errorf("Expected original repository 'example.com/test-image', got '%s'", img.Repository)
	}

	if img.Tag != "v1.0.0" {
		t.Errorf("Expected original tag 'v1.0.0', got '%s'", img.Tag)
	}
}

func TestMergePreservesNonOverriddenImages(t *testing.T) {
	// Override only one image; the other should survive unchanged
	overrideYAML := `
images:
  - name: test-image
    repository: override.com/test-image
    tag: "v3.0.0"
`

	base, err := imagevector.Read([]byte(testImagesYAML))
	if err != nil {
		t.Fatalf("Failed to read base image vector: %v", err)
	}

	override, err := imagevector.Read([]byte(overrideYAML))
	if err != nil {
		t.Fatalf("Failed to read override image vector: %v", err)
	}

	merged := imagevector.Merge(base, override)

	// Overridden image
	img, err := merged.FindImage("test-image")
	if err != nil {
		t.Fatalf("Failed to find test-image: %v", err)
	}

	if img.Repository != "override.com/test-image" {
		t.Errorf("Expected overridden repository 'override.com/test-image', got '%s'", img.Repository)
	}

	// Non-overridden image should be preserved
	img2, err := merged.FindImage("another-image")
	if err != nil {
		t.Fatalf("Failed to find another-image: %v", err)
	}

	if img2.Repository != "example.com/another-image" {
		t.Errorf("Expected original repository 'example.com/another-image', got '%s'", img2.Repository)
	}

	if img2.Tag != "v2.0.0" {
		t.Errorf("Expected original tag 'v2.0.0', got '%s'", img2.Tag)
	}
}
