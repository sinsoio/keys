package keys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sinsoio/sinso-mine/pkg/crypto"
	"github.com/sinsoio/sinso-mine/pkg/keystore"
	filekeystore "github.com/sinsoio/sinso-mine/pkg/keystore/file"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

const (
	keyHeaderKDF = "scrypt"
	keyVersion   = 3
)

// This format is compatible with Ethereum JSON v3 key file format.
type encryptedKey struct {
	Address string    `json:"address"`
	Crypto  keyCripto `json:"crypto"`
	Version int       `json:"version"`
	Id      string    `json:"id"`
}

type keyCripto struct {
	Cipher       string       `json:"cipher"`
	CipherText   string       `json:"ciphertext"`
	CipherParams cipherParams `json:"cipherparams"`
	KDF          string       `json:"kdf"`
	KDFParams    kdfParams    `json:"kdfparams"`
	MAC          string       `json:"mac"`
}
type cipherParams struct {
	IV string `json:"iv"`
}

type kdfParams struct {
	N     int    `json:"n"`
	R     int    `json:"r"`
	P     int    `json:"p"`
	DKLen int    `json:"dklen"`
	Salt  string `json:"salt"`
}

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
	filename := filepath.Join(path, "keys", "sinso.key")
	data, err := os.ReadFile(filename)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("file not exist")
	}

	pk, err = decryptKey(data, password)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

func ExportKeysString(password, path string) (publicKey, privateKey string, err error) {
	filename := filepath.Join(path, "keys", "sinso.key")
	data, err := os.ReadFile(filename)
	if err != nil && !os.IsNotExist(err) {
		return "", "", err
	}

	if len(data) == 0 {
		return "", "", fmt.Errorf("file not exist")
	}

	pk, err := decryptKey(data, password)
	if err != nil {
		return "", "", err
	}
	addr, err := crypto.NewEthereumAddress(pk.PublicKey)
	if err != nil {
		return "", "", err
	}
	publicKey = hex.EncodeToString(addr)
	privateKey = hex.EncodeToString(pk.D.Bytes())
	return publicKey, privateKey, nil
}

func decryptKey(data []byte, password string) (*ecdsa.PrivateKey, error) {
	var k encryptedKey
	if err := json.Unmarshal(data, &k); err != nil {
		return nil, err
	}
	if k.Version != keyVersion {
		return nil, fmt.Errorf("unsupported key version: %v", k.Version)
	}
	d, err := decryptData(k.Crypto, password)
	if err != nil {
		return nil, err
	}
	return crypto.DecodeSecp256k1PrivateKey(d)
}

func decryptData(v keyCripto, password string) ([]byte, error) {
	if v.Cipher != "aes-128-ctr" {
		return nil, fmt.Errorf("unsupported cipher: %v", v.Cipher)
	}

	mac, err := hex.DecodeString(v.MAC)
	if err != nil {
		return nil, fmt.Errorf("hex decode mac: %w", err)
	}
	cipherText, err := hex.DecodeString(v.CipherText)
	if err != nil {
		return nil, fmt.Errorf("hex decode cipher text: %w", err)
	}
	derivedKey, err := getKDFKey(v, []byte(password))
	if err != nil {
		return nil, err
	}
	calculatedMAC := sha3.Sum256(append(derivedKey[16:32], cipherText...))
	if !bytes.Equal(calculatedMAC[:], mac) {
		// if this fails we might be trying to load an ethereum V3 keyfile
		calculatedMACEth, err := crypto.LegacyKeccak256(append(derivedKey[16:32], cipherText...))
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(calculatedMACEth[:], mac) {
			return nil, keystore.ErrInvalidPassword
		}
	}

	iv, err := hex.DecodeString(v.CipherParams.IV)
	if err != nil {
		return nil, fmt.Errorf("hex decode IV cipher parameter: %w", err)
	}
	data, err := aesCTRXOR(derivedKey[:16], cipherText, iv)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func aesCTRXOR(key, inText, iv []byte) ([]byte, error) {
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(aesBlock, iv)
	outText := make([]byte, len(inText))
	stream.XORKeyStream(outText, inText)
	return outText, nil
}

func getKDFKey(v keyCripto, password []byte) ([]byte, error) {
	if v.KDF != keyHeaderKDF {
		return nil, fmt.Errorf("unsupported KDF: %s", v.KDF)
	}
	salt, err := hex.DecodeString(v.KDFParams.Salt)
	if err != nil {
		return nil, fmt.Errorf("hex decode salt: %w", err)
	}
	return scrypt.Key(
		password,
		salt,
		v.KDFParams.N,
		v.KDFParams.R,
		v.KDFParams.P,
		v.KDFParams.DKLen,
	)
}
