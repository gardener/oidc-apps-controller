// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestFetchStrIndexIfPresent(t *testing.T) {
	// Test case: Label is present
	t.Run("Label present", func(t *testing.T) {
		// Create a fake object with the label
		obj := &metav1.PartialObjectMetadata{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"statefulset.kubernetes.io/pod-name": "nginx-1-2",
				},
			},
		}

		// Call the function
		index := fetchStrIndexIfPresent(obj)

		// Assert the result
		assert.Equal(t, "2", index, "Expected index to be '2'")
	})

	// Test case: Label is present with double digit index
	t.Run("Label present with double digit index", func(t *testing.T) {
		// Create a fake object with the label
		obj := &metav1.PartialObjectMetadata{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"statefulset.kubernetes.io/pod-name": "nginx-1-20",
				},
			},
		}

		// Call the function
		index := fetchStrIndexIfPresent(obj)

		// Assert the result
		assert.Equal(t, "20", index, "Expected index to be '20'")
	})

	// Test case: Label is missing
	t.Run("Label missing", func(t *testing.T) {
		// Create a fake object without the label
		obj := &metav1.PartialObjectMetadata{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{},
			},
		}

		// Call the function
		index := fetchStrIndexIfPresent(obj)

		// Assert the result
		assert.Equal(t, "", index, "Expected index to be an empty string")
	})
}
