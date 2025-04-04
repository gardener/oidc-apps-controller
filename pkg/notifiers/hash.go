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
