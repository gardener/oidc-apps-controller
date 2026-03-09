// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package imagevector

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// OverrideEnv is the name of the environment variable containing the path to the image vector override file.
	OverrideEnv = "IMAGEVECTOR_OVERWRITE"
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
		if strings.HasPrefix(i.Tag, "sha256:") {
			return fmt.Sprintf("%s@%s", i.Repository, i.Tag)
		}

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

// ReadFile reads the YAML image vector from the given file path.
func ReadFile(path string) (ImageVector, error) {
	// #nosec G304 G703 //nolint:gosec // The file path is controlled.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read image vector file %q: %w", path, err)
	}

	return Read(data)
}

// Merge merges the override ImageVector into the base ImageVector.
// Images from the override vector replace images with the same name in the base vector.
func Merge(base, override ImageVector) ImageVector {
	baseVec, ok := base.(*imageVector)
	if !ok {
		return base
	}

	overrideVec, ok := override.(*imageVector)
	if !ok {
		return base
	}

	merged := make(map[string]*Image, len(baseVec.images))
	maps.Copy(merged, baseVec.images)

	for name, img := range overrideVec.images {
		if existing, ok := merged[name]; ok {
			mergedImg := &Image{
				Name:             existing.Name,
				Repository:       existing.Repository,
				Tag:              existing.Tag,
				SourceRepository: existing.SourceRepository,
			}

			if img.Repository != "" {
				mergedImg.Repository = img.Repository
			}

			if img.Tag != "" {
				mergedImg.Tag = img.Tag
			}

			if img.SourceRepository != "" {
				mergedImg.SourceRepository = img.SourceRepository
			}

			merged[name] = mergedImg
		} else {
			merged[name] = img
		}
	}

	return &imageVector{images: merged}
}

// WithEnvOverride returns a new ImageVector with overrides applied from a YAML file.
// The env parameter is the name of the environment variable that contains the path to the override file.
// If the environment variable is not set, the original vector is returned unchanged.
func WithEnvOverride(vec ImageVector, env string) (ImageVector, error) {
	overwritePath := os.Getenv(env)
	if len(overwritePath) == 0 {
		return vec, nil
	}

	override, err := ReadFile(overwritePath)
	if err != nil {
		return nil, err
	}

	return Merge(vec, override), nil
}
