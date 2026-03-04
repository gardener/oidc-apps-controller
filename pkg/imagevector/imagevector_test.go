// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package imagevector_test

import (
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
	// Set up environment variables
	t.Setenv("IMAGEVECTOR_OVERRIDE_TEST_IMAGE_REPOSITORY", "override.com/test-image")
	t.Setenv("IMAGEVECTOR_OVERRIDE_TEST_IMAGE_TAG", "v3.0.0")

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
