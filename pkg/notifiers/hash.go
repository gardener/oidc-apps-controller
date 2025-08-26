// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package notifiers

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func getFileSha256(filePath string) string {
	stat, err := os.Stat(filePath)
	if err != nil {
		_log.Error(err, "cannot stat file path", "path", filePath)

		return ""
	}

	if stat.IsDir() {
		return ""
	}

	hash := sha256.New()
	filePath = filepath.Clean(filePath)
	f, err := os.Open(filePath)

	defer func() {
		if err = f.Close(); err != nil {
			_log.Error(err, "error closing file", "path", filePath)
		}
	}()

	if err != nil {
		_log.Error(err, "error opening file", "path", filePath)

		return ""
	}

	if _, err = io.Copy(hash, f); err != nil {
		_log.Error(err, "error reading file", "path", filePath)

		return ""
	}

	s := fmt.Sprintf("%x", hash.Sum(nil))

	return s
}
