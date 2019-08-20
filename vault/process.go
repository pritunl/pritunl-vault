package vault

import (
	"encoding/json"

	"github.com/dropbox/godropbox/errors"
	"github.com/pritunl/pritunl-vault/errortypes"
)

func (v *Vault) ProcessData(payload *Payload) (out *Payload, err error) {
	plaintext, err := v.decryptPayload(payload)
	if err != nil {
		return
	}

	data := &Data{}

	err = json.Unmarshal(plaintext, data)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Failed to unmarshal data"),
		}
		return
	}

	valid, err := v.validate(data)
	if err != nil {
		return
	}

	if !valid {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Invalid data signature"),
		}
		return
	}

	for _, item := range data.Items {
		switch item.Operation {
		case Decrypt:
			err = item.decrypt(v)
			if err != nil {
				return
			}
			break
		case Encrypt:
			err = item.encrypt(v)
			if err != nil {
				return
			}
			break
		case Sign:
			err = item.sign(v)
			if err != nil {
				return
			}
			break
		case Verify:
			err = item.verify(v)
			if err != nil {
				return
			}
			break
		}
	}

	err = v.authorize(data)
	if err != nil {
		return
	}

	outData, err := json.Marshal(data)
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "vault: Marshal json error"),
		}
		return
	}

	out, err = v.encryptPayload(outData)
	if err != nil {
		return
	}

	return
}
