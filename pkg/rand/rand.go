// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package rand

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"strings"
)

const charset = "abcdefghijklmnopqrstuvwxyz0123456789"

// GenerateRandomString generates a random string with a given length
func GenerateRandomString(length int) string {
	var b strings.Builder

	b.Grow(length)

	charsetLength := big.NewInt(int64(len(charset)))
	for i := 0; i < length; i++ {
		index, err := rand.Int(rand.Reader, charsetLength)
		if err != nil {
			return ""
		}

		_ = b.WriteByte(charset[index.Int64()])
	}

	return b.String()
}

// GenerateSha256 returns a sha256 hash of a given string
func GenerateSha256(key string) string {
	hash := sha256.New()
	if _, err := io.Copy(hash, strings.NewReader(key)); err != nil {
		return ""
	}

	s := fmt.Sprintf("%x", hash.Sum(nil))
	if len(s) > 6 {
		return s[:6]
	}

	return s
}

// GenerateFullSha256 returns a sha256 hash of a given string
func GenerateFullSha256(key string) string {
	hash := sha256.New()
	if _, err := io.Copy(hash, strings.NewReader(key)); err != nil {
		return ""
	}

	return fmt.Sprintf("%x", hash.Sum(nil))
}
