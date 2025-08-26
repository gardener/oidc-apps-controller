// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package configuration

import (
	_ "embed"

	"gopkg.in/yaml.v2"
)

//go:embed templates/rbac-proxy-resource-attributes.yaml
var rbac string

type root struct {
	Authorization Authorization `yaml:"authorization"`
}

// Authorization holds the ResourceAttributes used by the kube-rbac-proxy to create SubjectAccessReviews for the incoming authenticated (but not yet) authorized requests.
type Authorization struct {
	ResourceAttributes ResourceAttributes `yaml:"resourceAttributes"`
}

// ResourceAttributes holds the resource definition
type ResourceAttributes struct {
	APIGroup    string `yaml:"apiGroup"`
	APIVersion  string `yaml:"apiVersion"`
	Resource    string `yaml:"resource"`
	Subresource string `yaml:"subresource"`
	Namespace   string `yaml:"namespace"`
}

func (r *root) Parse() string {
	var parsed []byte

	parsed, _ = yaml.Marshal(*r)

	return string(parsed)
}

// OptRAttributes is a function that modifies the ResourceAttributes
type OptRAttributes func(*ResourceAttributes)

// NewResourceAttributes returns a new configParser for the ResourceAttributes
func NewResourceAttributes(opt ...OptRAttributes) configParser {
	root := &root{
		Authorization: Authorization{
			ResourceAttributes: ResourceAttributes{
				APIGroup:    "",
				APIVersion:  "",
				Resource:    "",
				Subresource: "",
				Namespace:   "",
			},
		},
	}
	_ = yaml.Unmarshal([]byte(rbac), &root)

	for _, o := range opt {
		o(&root.Authorization.ResourceAttributes)
	}

	return root
}

// WithNamespace sets the namespace for the ResourceAttributes
func WithNamespace(namespace string) OptRAttributes {
	return func(r *ResourceAttributes) {
		r.Namespace = namespace
	}
}

// WithSubresource sets the subresource for the ResourceAttributes
func WithSubresource(subresource string) OptRAttributes {
	return func(r *ResourceAttributes) {
		r.Subresource = subresource
	}
}
