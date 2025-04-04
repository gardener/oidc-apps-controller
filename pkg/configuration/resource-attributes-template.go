// Copyright 2024 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

type optRAttributes func(*ResourceAttributes)

// NewResourceAttributes returns a new configParser for the ResourceAttributes
func NewResourceAttributes(opt ...optRAttributes) configParser {
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
func WithNamespace(namespace string) optRAttributes {
	return func(r *ResourceAttributes) {
		r.Namespace = namespace
	}
}

// WithSubresource sets the subresource for the ResourceAttributes
func WithSubresource(subresource string) optRAttributes {
	return func(r *ResourceAttributes) {
		r.Subresource = subresource
	}
}
