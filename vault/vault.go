package vault

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"

	"github.com/dropbox/godropbox/errors"
	"github.com/pritunl/pritunl-vault/constants"
	"github.com/pritunl/pritunl-vault/errortypes"
	"github.com/pritunl/pritunl-vault/utils"
	"golang.org/x/crypto/pbkdf2"
)

var (
	Primary *Vault
)

type Vault struct {
	hostKey       *rsa.PrivateKey
	hostKeyPub    []byte
	serverKey     *rsa.PrivateKey
	serverKeyPub  []byte
	clientKeyPub  *rsa.PublicKey
	authorizeKey  []byte
	encryptionKey []byte

	cryptoNonce []byte
	cryptoData  []byte
	aesKey      []byte
	hmacKey     []byte

	initKeyRead     bool
	hostKeyLoaded   bool
	masterKeyLoaded bool
	serverKeyRead   bool
}

func (v *Vault) Init() (err error) {
	v.authorizeKey, err = utils.RandBytes(32)
	if err != nil {
		err = &errortypes.ReadError{
			errors.Wrap(err, "vault: Failed to generate authorize key"),
		}
		return
	}

	v.encryptionKey, err = utils.RandBytes(32)
	if err != nil {
		err = &errortypes.ReadError{
			errors.Wrap(err, "vault: Failed to generate encryption key"),
		}
		return
	}

	clientKeyData, err := base64.StdEncoding.DecodeString(constants.ClientKey)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to decode client key"),
		}
		return
	}

	clientKeyBlock, _ := pem.Decode(clientKeyData)

	v.clientKeyPub, err = x509.ParsePKCS1PublicKey(clientKeyBlock.Bytes)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to parse client public key"),
		}
		return
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		err = &errortypes.ReadError{
			errors.Wrap(err, "vault: Failed to generate private key"),
		}
		return
	}

	v.serverKey = serverKey

	pubServerKeyByte := x509.MarshalPKCS1PublicKey(&serverKey.PublicKey)
	pubServerKeyBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubServerKeyByte,
	}
	v.serverKeyPub = pem.EncodeToMemory(pubServerKeyBlock)

	return
}

func (v *Vault) GetInitKey() (initKeyData string, err error) {
	if v.initKeyRead {
		err = &errortypes.ReadError{
			errors.New("vault: Init key already read"),
		}
		return
	}
	v.initKeyRead = true

	initKey := []string{
		base64.StdEncoding.EncodeToString(v.authorizeKey),
		base64.StdEncoding.EncodeToString(v.encryptionKey),
	}

	initKeyJson, err := json.Marshal(initKey)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to encode init key data"),
		}
		return
	}

	ciphertext, err := rsa.EncryptOAEP(
		sha512.New(),
		rand.Reader,
		v.clientKeyPub,
		initKeyJson,
		[]byte{},
	)
	if err != nil {
		err = &errortypes.WriteError{
			errors.Wrap(err, "vault: Failed to encrypt init key data"),
		}
		return
	}

	initKeyData = base64.StdEncoding.EncodeToString(ciphertext)

	return
}

func (v *Vault) LoadHostKey(payload *Payload) (err error) {
	if v.hostKeyLoaded {
		err = &errortypes.ReadError{
			errors.New("vault: Host key already loaded"),
		}
		return
	}
	v.hostKeyLoaded = true

	data, err := v.decryptPayload(payload)
	if err != nil {
		return
	}

	key := &ServerKey{}

	err = json.Unmarshal(data, key)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to parse server key"),
		}
		return
	}

	valid, err := v.validateServerKey(key)
	if err != nil {
		return
	}

	if !valid {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Invalid server key signature"),
		}
		return
	}

	hostKey, err := base64.StdEncoding.DecodeString(key.HostKey)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to decode host key"),
		}
		return
	}

	hostKeyBlock, _ := pem.Decode(hostKey)

	v.hostKey, err = x509.ParsePKCS1PrivateKey(hostKeyBlock.Bytes)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to parse host key"),
		}
		return
	}

	pubHostKeyByte := x509.MarshalPKCS1PublicKey(&v.hostKey.PublicKey)
	pubHostKeyBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubHostKeyByte,
	}
	v.hostKeyPub = pem.EncodeToMemory(pubHostKeyBlock)

	return
}

func (v *Vault) loadCryptoKeys(key *MasterKey) (err error) {
	passphrase, err := v.decryptMasterKey(key)
	if err != nil {
		return
	}

	masterKey := pbkdf2.Key(
		passphrase,
		[]byte("pritunl-vault"),
		4096,
		32,
		sha512.New,
	)

	var keys *CryptoKeys
	if key.CryptoKeys != "" {
		split := strings.SplitN(key.CryptoKeys, "$", 2)
		if len(split) != 2 {
			err = &errortypes.ParseError{
				errors.Wrap(err, "vault: Failed to split crypto key input"),
			}
			return
		}

		v.cryptoNonce, err = base64.StdEncoding.DecodeString(split[0])
		if err != nil {
			err = &errortypes.ParseError{
				errors.Wrap(err, "vault: Failed to decode crypto key nonce"),
			}
			return
		}

		v.cryptoData, err = base64.StdEncoding.DecodeString(split[1])
		if err != nil {
			err = &errortypes.ParseError{
				errors.Wrap(err, "vault: Failed to decode crypto data nonce"),
			}
			return
		}

		keys, err = v.decryptCryptoKeys(masterKey)
		if err != nil {
			return
		}
	} else {
		keys = &CryptoKeys{}
	}

	changed := false
	if keys.AesKey == "" {
		changed = true

		v.aesKey, err = utils.RandBytes(32)
		if err != nil {
			err = &errortypes.ReadError{
				errors.Wrap(err, "vault: Failed to generate aes key"),
			}
			return
		}

		keys.AesKey = base64.StdEncoding.EncodeToString(v.aesKey)
	} else {
		v.aesKey, err = base64.StdEncoding.DecodeString(keys.AesKey)
		if err != nil {
			err = &errortypes.ParseError{
				errors.Wrap(err, "vault: Failed to decode aes key"),
			}
			return
		}
	}

	if keys.HmacKey == "" {
		changed = true

		v.hmacKey, err = utils.RandBytes(32)
		if err != nil {
			err = &errortypes.ReadError{
				errors.Wrap(err, "vault: Failed to generate hmac key"),
			}
			return
		}

		keys.HmacKey = base64.StdEncoding.EncodeToString(v.hmacKey)
	} else {
		v.hmacKey, err = base64.StdEncoding.DecodeString(keys.HmacKey)
		if err != nil {
			err = &errortypes.ParseError{
				errors.Wrap(err, "vault: Failed to decode hmac key"),
			}
			return
		}
	}

	if changed {
		cryptoData, e := v.encryptCryptoKeys(masterKey)
		if e != nil {
			err = e
			return
		}

		v.cryptoData = cryptoData
	}

	return
}

func (v *Vault) LoadMasterKey(payload *Payload) (err error) {
	if v.masterKeyLoaded {
		err = &errortypes.ReadError{
			errors.New("vault: Master key already loaded"),
		}
		return
	}
	v.masterKeyLoaded = true

	data, err := v.decryptPayload(payload)
	if err != nil {
		return
	}

	key := &MasterKey{}

	err = json.Unmarshal(data, key)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to parse master key"),
		}
		return
	}

	valid, err := v.validateMasterKey(key)
	if err != nil {
		return
	}

	if !valid {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Invalid server key signature"),
		}
		return
	}

	err = v.loadCryptoKeys(key)
	if err != nil {
		return
	}

	return
}

func (v *Vault) GetServerKey() (payload *Payload, err error) {
	if v.serverKeyRead {
		err = &errortypes.ReadError{
			errors.New("vault: Server key already read"),
		}
		return
	}
	v.serverKeyRead = true

	serverKey := &ServerKey{
		HostKey:   string(v.hostKeyPub),
		ServerKey: string(v.serverKeyPub),
	}

	err = v.authorizeServerKey(serverKey)
	if err != nil {
		return
	}

	data, err := json.Marshal(serverKey)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Marshal json error"),
		}
		return
	}

	payload, err = v.encryptPayload(data)
	if err != nil {
		return
	}

	return
}
