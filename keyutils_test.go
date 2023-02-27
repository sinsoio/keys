// Copyright 2022 The Sinso Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package keys_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sinsoio/keys"
)

func TestCreate(t *testing.T) {
	keys.GeneratePrivateKey("123", "./")
}

func TestImportSuccess(t *testing.T) {
	filename := filepath.Join("./keys/sinso.key")
	os.Remove(filename)
	pk, create, err := keys.ImportPrivateKey("123", "./", "381b904e945819291614a2de3b0a17330ad83e0b7f4b2f2719ac1fa46123af82")
	if err != nil {
		t.Error(err)
	}

	if !create {
		t.Error("not create")
	}

	t.Logf("public:%v", pk.PublicKey)
}

func TestImportFailed(t *testing.T) {
	_, _, err := keys.ImportPrivateKey("123", "./", "381b904e945819291614a2de3b0a17330ad83e0b7f4b2f2719ac1fa46123af82")
	if err != nil {
		t.Log(err)
	}
}

func TestExport(t *testing.T) {
	t.Log(keys.ExportPrivateKey("", "./"))
}

func TestExportString(t *testing.T) {
	t.Log(keys.ExportKeysString("", "./"))
}
