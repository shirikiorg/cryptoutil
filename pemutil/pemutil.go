package pemutil

import (
	"encoding/pem"
	"errors"
)

// ErNoPEMBlock is the error returned when decoding couldn't find a valid
// PEM block in the input.
var ErrNoPEMBlock = errors.New("no PEM block found in input")

// ErrInvalidPublicKey is the error returned when failing to encode
// a private key
var ErrInvalidPublicKey = errors.New("invalid public key")

// ErrInvalidPrivateKet is the error returned when failing to encode
// a public key
var ErrInvalidPrivateKey = errors.New("invalid private key")

// EnocePrivate encodes a private key in DER form to PEM blocks
func EncodePrivateKey(key []byte) ([]byte, error) {

	blockBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: key,
	})

	if blockBytes == nil {
		return nil, ErrInvalidPrivateKey
	}

	return blockBytes, nil
}

// EncodePublicKey encodes a public key in DER form to PEM blocks
func EncodePublicKey(key []byte) ([]byte, error) {

	blockBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: key,
	})

	if blockBytes == nil {
		return nil, ErrInvalidPublicKey
	}

	return blockBytes, nil
}

// Decode decodes a PEM key to its original format
func Decode(key []byte) ([]byte, error) {

	block, _ := pem.Decode(key)
	if block == nil {
		return nil, ErrNoPEMBlock
	}
	return block.Bytes, nil
}
