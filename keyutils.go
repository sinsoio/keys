// Copyright 2022 The Sinso Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package keys

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"path/filepath"

	"github.com/sinsoio/keys/crypto"
	filekeystore "github.com/sinsoio/keys/keystore/file"
)

func GeneratePrivateKey(password, path string) (k *ecdsa.PrivateKey, created bool, err error) {
	keystore := filekeystore.New(filepath.Join(path, "keys"))
	return keystore.Key("sinso", password, "")
}

func ImportPrivateKey(password, path, privatekey string) (k *ecdsa.PrivateKey, created bool, err error) {
	keystore := filekeystore.New(filepath.Join(path, "keys"))
	exist, err := keystore.Exists("sinso")
	if err != nil {
		return nil, false, err
	}

	if exist {
		return nil, false, fmt.Errorf("file exist")
	}

	return keystore.Key("sinso", password, privatekey)
}

func ExportPrivateKey(password, path string) (pk *ecdsa.PrivateKey, err error) {
	keystore := filekeystore.New(filepath.Join(path, "keys"))
	pk, _, err = keystore.Key("sinso", password, "")
	if err != nil {
		return nil, err
	}
	return pk, nil
}

func ExportKeysString(password, path string) (publicKey, privateKey string, err error) {
	keystore := filekeystore.New(filepath.Join(path, "keys"))
	pk, _, err := keystore.Key("sinso", password, "")
	if err != nil {
		return "", "", err
	}

	addr := crypto.NewEthereumAddress(pk.PublicKey)
	if err != nil {
		return "", "", err
	}
	publicKey = hex.EncodeToString(addr)

	privateKey = hex.EncodeToString(crypto.EncodeSecp256k1PrivateKey(pk))
	return publicKey, privateKey, nil
}
