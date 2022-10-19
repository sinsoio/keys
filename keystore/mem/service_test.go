// Copyright 2022 The Sinso Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mem_test

import (
	"testing"

	"github.com/sinsoio/keys/keystore/mem"
	"github.com/sinsoio/keys/keystore/test"
)

func TestService(t *testing.T) {
	test.Service(t, mem.New())
}
