// Copyright 2022 The Sinso Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package file_test

import (
	"os"
	"testing"

	"github.com/sinsoio/keys/keystore/file"
	"github.com/sinsoio/keys/keystore/test"
)

func TestService(t *testing.T) {
	dir, err := os.MkdirTemp("", "sinso-keystore-file-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	test.Service(t, file.New(dir))
}
