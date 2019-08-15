package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dropbox/godropbox/errors"
	"github.com/pritunl/pritunl-vault/errortypes"
	"github.com/pritunl/pritunl-vault/nonces"
	"github.com/pritunl/pritunl-vault/utils"
	"golang.org/x/crypto/pbkdf2"
)

func (v *Vault) validate(in *Input) (valid bool, err error) {
	if nonces.Contains(in.Nonce) {
		return
	}

	now := time.Now().Unix()
	diff := now - in.Timestamp
	if diff > 10 || diff < -3 {
		return
	}

	input := in.Nonce + "&" + fmt.Sprintf("%d", in.Timestamp) + "&" +
		in.Collection + "&" + in.Id + "&" + in.Key + "&" + in.Value

	if in.Signature != "" {
		input += "&" + in.Signature
	}

	hashFunc := hmac.New(sha512.New, v.authorizeKey)
	hashFunc.Write([]byte(input))
	hashData := hashFunc.Sum(nil)

	authorization := base64.StdEncoding.EncodeToString(hashData)

	if subtle.ConstantTimeCompare(
		[]byte(in.Authorization),
		[]byte(authorization),
	) == 1 {
		valid = true
	}

	return
}

func (v *Vault) authorize(out *Output) (err error) {
	nonce, err := utils.RandStr(16)
	if err != nil {
		return
	}

	out.Timestamp = time.Now().Unix()
	out.Nonce = nonce

	input := out.Nonce + "&" + fmt.Sprintf("%d", out.Timestamp) + "&" +
		out.Collection + "&" + out.Id + "&" + out.Key + "&" + out.Value

	if out.Signature != "" {
		input += "&" + out.Signature
	}

	hashFunc := hmac.New(sha512.New, v.authorizeKey)
	hashFunc.Write([]byte(input))
	hashData := hashFunc.Sum(nil)

	out.Authorization = base64.StdEncoding.EncodeToString(hashData)

	return
}

func (v *Vault) validateServerKey(key *ServerKey) (valid bool, err error) {
	if nonces.Contains(key.Nonce) {
		return
	}

	now := time.Now().Unix()
	diff := now - key.Timestamp
	if diff > 10 || diff < -3 {
		return
	}

	input := key.Nonce + "&" + fmt.Sprintf("%d", key.Timestamp) + "&" +
		key.HostKey

	if key.ServerKey != "" {
		input += "&" + key.ServerKey
	}

	hashFunc := hmac.New(sha512.New, v.authorizeKey)
	hashFunc.Write([]byte(input))
	hashData := hashFunc.Sum(nil)

	authorization := base64.StdEncoding.EncodeToString(hashData)

	if subtle.ConstantTimeCompare(
		[]byte(key.Authorization),
		[]byte(authorization),
	) == 1 {
		valid = true
	}

	return
}

func (v *Vault) validateMasterKey(key *MasterKey) (valid bool, err error) {
	if nonces.Contains(key.Nonce) {
		return
	}

	now := time.Now().Unix()
	diff := now - key.Timestamp
	if diff > 10 || diff < -3 {
		return
	}

	input := key.Nonce + "&" + fmt.Sprintf("%d", key.Timestamp) + "&" +
		key.HostSecret + "&" + key.ServerSecret + "&" +
		key.ClientSecret + "&" + key.MasterNonce + "&" + key.MasterKey

	hashFunc := hmac.New(sha512.New, v.authorizeKey)
	hashFunc.Write([]byte(input))
	hashData := hashFunc.Sum(nil)

	authorization := base64.StdEncoding.EncodeToString(hashData)

	if subtle.ConstantTimeCompare(
		[]byte(key.Authorization),
		[]byte(authorization),
	) == 1 {
		valid = true
	}

	return
}

func (v *Vault) authorizeServerKey(key *ServerKey) (err error) {
	nonce, err := utils.RandStr(16)
	if err != nil {
		return
	}

	key.Timestamp = time.Now().Unix()
	key.Nonce = nonce

	input := key.Nonce + "&" + fmt.Sprintf("%d", key.Timestamp) + "&" +
		key.HostKey

	if key.ServerKey != "" {
		input += "&" + key.ServerKey
	}

	hashFunc := hmac.New(sha512.New, v.authorizeKey)
	hashFunc.Write([]byte(input))
	hashData := hashFunc.Sum(nil)

	key.Authorization = base64.StdEncoding.EncodeToString(hashData)

	return
}

func (v *Vault) validateMasterKeyData(secret []byte, key *MasterKeyData) (
	valid bool, err error) {

	hashFunc := hmac.New(sha512.New, secret)
	hashFunc.Write([]byte(key.MasterKey))
	hashData := hashFunc.Sum(nil)

	authorization := base64.StdEncoding.EncodeToString(hashData)

	if subtle.ConstantTimeCompare(
		[]byte(key.Authorization),
		[]byte(authorization),
	) == 1 {
		valid = true
	}

	return
}

func (v *Vault) encryptPayload(data []byte) (payload *Payload, err error) {
	block, err := aes.NewCipher(v.encryptionKey)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to parse encryption key"),
		}
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to parse encryption block"),
		}
		return
	}

	nonce, err := utils.RandBytes(12)
	if err != nil {
		return
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)

	payload = &Payload{
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		Data:  base64.StdEncoding.EncodeToString(ciphertext),
	}

	return
}

func (v *Vault) decryptPayload(payload *Payload) (data []byte, err error) {
	block, err := aes.NewCipher(v.encryptionKey)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to parse encryption key"),
		}
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to parse encryption block"),
		}
		return
	}

	nonce, err := base64.StdEncoding.DecodeString(payload.Nonce)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to parse payload nonce"),
		}
		return
	}

	ciphertext, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to parse payload data"),
		}
		return
	}

	data, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to parse encryption block"),
		}
		return
	}

	return
}

func (v *Vault) decryptMasterKey(key *MasterKey) (master []byte, err error) {
	hostCiphertext, err := base64.StdEncoding.DecodeString(key.HostSecret)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to decode host key"),
		}
		return
	}

	hostSecret, err := rsa.DecryptOAEP(
		sha512.New(),
		rand.Reader,
		v.hostKey,
		hostCiphertext,
		[]byte{},
	)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to decrypt host key"),
		}
		return
	}

	serverCiphertext, err := base64.StdEncoding.DecodeString(key.ServerSecret)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to decode server key"),
		}
		return
	}

	serverSecret, err := rsa.DecryptOAEP(
		sha512.New(),
		rand.Reader,
		v.serverKey,
		serverCiphertext,
		[]byte{},
	)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to decrypt server key"),
		}
		return
	}

	hostSecretSplit := strings.SplitN(string(hostSecret), "&", 2)
	if len(hostSecretSplit) != 2 {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Invalid host secret"),
		}
		return
	}
	serverSecretSplit := strings.SplitN(string(serverSecret), "&", 2)
	if len(serverSecretSplit) != 2 {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Invalid server secret"),
		}
		return
	}
	clientSecretSplit := strings.SplitN(key.ClientSecret, "&", 2)
	if len(clientSecretSplit) != 2 {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Invalid client secret"),
		}
		return
	}

	secret := pbkdf2.Key(
		[]byte(hostSecretSplit[1]+serverSecretSplit[1]+clientSecretSplit[1]),
		[]byte(hostSecretSplit[0]+serverSecretSplit[0]+clientSecretSplit[0]),
		4096,
		32,
		sha512.New,
	)

	block, err := aes.NewCipher(secret)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to parse encryption key"),
		}
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to parse encryption block"),
		}
		return
	}

	nonce, err := base64.StdEncoding.DecodeString(key.MasterNonce)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to parse payload nonce"),
		}
		return
	}

	ciphertext, err := base64.StdEncoding.DecodeString(key.MasterKey)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to parse payload data"),
		}
		return
	}

	masterKeyPlaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to parse encryption block"),
		}
		return
	}

	masterKeyData := &MasterKeyData{}

	err = json.Unmarshal(masterKeyPlaintext, masterKeyData)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to parse master key data"),
		}
		return
	}

	valid, err := v.validateMasterKeyData(secret, masterKeyData)
	if err != nil {
		return
	}

	if !valid {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Invalid master key signature"),
		}
		return
	}

	master = []byte(masterKeyData.MasterKey)

	return
}
