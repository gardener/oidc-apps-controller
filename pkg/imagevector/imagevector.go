// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package imagevector

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// OverrideEnv is the environment variable prefix used for image overrides.
	OverrideEnv = "IMAGEVECTOR_OVERRIDE"
)

// ImageVector is a collection of image definitions.
type ImageVector interface {
	FindImage(name string) (*Image, error)
}

// Image represents a container image with its repository and tag.
type Image struct {
	Name             string `yaml:"name" json:"name"`
	Repository       string `yaml:"repository" json:"repository"`
	Tag              string `yaml:"tag" json:"tag"`
	SourceRepository string `yaml:"sourceRepository,omitempty" json:"sourceRepository,omitempty"`
}

// String returns the full image reference.
func (i *Image) String() string {
	if i.Tag != "" {
		return fmt.Sprintf("%s:%s", i.Repository, i.Tag)
	}

	return i.Repository
}

type imageVector struct {
	images map[string]*Image
}

type imagesYAML struct {
	Images []*Image `yaml:"images"`
}

// FindImage returns the image with the given name.
func (v *imageVector) FindImage(name string) (*Image, error) {
	img, ok := v.images[name]
	if !ok {
		return nil, fmt.Errorf("image %q not found", name)
	}

	return img, nil
}

// Read parses the YAML image vector data.
func Read(data []byte) (ImageVector, error) {
	var imagesYAML imagesYAML
	if err := yaml.Unmarshal(data, &imagesYAML); err != nil {
		return nil, fmt.Errorf("failed to unmarshal image vector: %w", err)
	}

	images := make(map[string]*Image, len(imagesYAML.Images))
	for _, img := range imagesYAML.Images {
		if img.Name == "" {
			return nil, errors.New("image name cannot be empty")
		}

		images[img.Name] = img
	}

	return &imageVector{images: images}, nil
}

// WithEnvOverride returns a new ImageVector with environment variable overrides applied.
// Environment variables should be in the format: <envPrefix>_<IMAGE_NAME>_REPOSITORY and <envPrefix>_<IMAGE_NAME>_TAG
// For example: IMAGEVECTOR_OVERRIDE_OAUTH2_PROXY_REPOSITORY=my.registry.com/oauth2-proxy
func WithEnvOverride(vec ImageVector, envPrefix string) (ImageVector, error) {
	baseVec, ok := vec.(*imageVector)
	if !ok {
		return vec, nil
	}

	// Create a copy of the image map
	overriddenImages := make(map[string]*Image, len(baseVec.images))
	for name, img := range baseVec.images {
		// Create a copy of the image
		imgCopy := &Image{
			Name:             img.Name,
			Repository:       img.Repository,
			Tag:              img.Tag,
			SourceRepository: img.SourceRepository,
		}

		// Check for repository override
		envVarName := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))

		repoEnvKey := fmt.Sprintf("%s_%s_REPOSITORY", envPrefix, envVarName)
		if repoOverride := os.Getenv(repoEnvKey); repoOverride != "" {
			imgCopy.Repository = repoOverride
		}

		// Check for tag override
		tagEnvKey := fmt.Sprintf("%s_%s_TAG", envPrefix, envVarName)
		if tagOverride := os.Getenv(tagEnvKey); tagOverride != "" {
			imgCopy.Tag = tagOverride
		}

		overriddenImages[name] = imgCopy
	}

	return &imageVector{images: overriddenImages}, nil
}
