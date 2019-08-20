package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"strings"

	"github.com/dropbox/godropbox/errors"
	"github.com/pritunl/pritunl-vault/errortypes"
	"github.com/pritunl/pritunl-vault/utils"
)

func (i *Item) encrypt(v *Vault) (err error) {
	block, err := aes.NewCipher(v.aesKey)
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

	ciphertext := gcm.Seal(nil, nonce, []byte(i.Value), nil)

	i.Value = "$SEAV1$&" + base64.StdEncoding.EncodeToString(nonce) + "&" +
		base64.StdEncoding.EncodeToString(ciphertext)

	hashFunc := hmac.New(sha512.New, v.hmacKey)
	hashFunc.Write([]byte(i.Collection + "&" + i.Id + "&" +
		i.Key + "&" + i.Value))
	hashData := hashFunc.Sum(nil)

	i.Signature = base64.StdEncoding.EncodeToString(hashData)

	return
}

func (i *Item) decrypt(v *Vault) (err error) {
	hashFunc := hmac.New(sha512.New, v.hmacKey)
	hashFunc.Write([]byte(i.Collection + "&" + i.Id + "&" +
		i.Key + "&" + i.Value))
	hashData := hashFunc.Sum(nil)

	authorization := base64.StdEncoding.EncodeToString(hashData)

	if subtle.ConstantTimeCompare(
		[]byte(i.Signature),
		[]byte(authorization),
	) != 1 {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Invalid item signature"),
		}
		return
	}

	ciphertexts := strings.SplitN(i.Value, "&", 3)
	if len(ciphertexts) != 3 {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Invalid encrypted value"),
		}
		return
	}

	if ciphertexts[0] != "$SEAV1$" {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Unknown encryption"),
		}
		return
	}

	nonce, err := base64.StdEncoding.DecodeString(ciphertexts[1])
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to parse nonce"),
		}
		return
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertexts[2])
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to parse ciphertext"),
		}
		return
	}

	block, err := aes.NewCipher(v.aesKey)
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

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to decrypt value"),
		}
		return
	}

	i.Value = string(plaintext)

	return
}

func (i *Item) sign(v *Vault) (err error) {
	hashFunc := hmac.New(sha512.New, v.hmacKey)
	hashFunc.Write([]byte(i.Collection + "&" + i.Id + "&" +
		i.Key + "&" + i.Value))
	hashData := hashFunc.Sum(nil)

	i.Signature = base64.StdEncoding.EncodeToString(hashData)

	return
}

func (i *Item) verify(v *Vault) (err error) {
	hashFunc := hmac.New(sha512.New, v.hmacKey)
	hashFunc.Write([]byte(i.Collection + "&" + i.Id + "&" +
		i.Key + "&" + i.Value))
	hashData := hashFunc.Sum(nil)

	authorization := base64.StdEncoding.EncodeToString(hashData)

	if subtle.ConstantTimeCompare(
		[]byte(i.Signature),
		[]byte(authorization),
	) != 1 {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Invalid item signature"),
		}
		return
	}

	return
}
