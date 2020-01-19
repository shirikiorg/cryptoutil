package ecdsautil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"io"

	"github.com/pkg/errors"
	"github.com/shirikiorg/cryptoutil/pemutil"
)

// ErrKeyNotECDSA is the error returned when trying to decode a non ECDSA key
var ErrKeyNotECDSA = errors.New("key is not ECDSA")

// GenererateKeyBytes generates a key pair and returns the bytes for the
// private key and the public key. Private key and public key are returned as
// PEM encoded form.
func GenerateKeyBytes(c elliptic.Curve, seed io.Reader) ([]byte, []byte, error) {

	privateKey, err := ecdsa.GenerateKey(c, seed)
	if err != nil {
		return nil, nil, errors.Wrap(
			err,
			"error while generating ecdsa key pair",
		)
	}

	return EncodeKey(privateKey, &privateKey.PublicKey)
}

// EncodeKey encodes a given pair of ECDSA key to PEM blocks
func EncodeKey(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([]byte, []byte, error) {

	pemEncodedPrivate, err := EncodePrivateKey(privateKey)
	if err != nil {
		return nil, nil, errors.Wrap(
			err,
			"error while encoding private key",
		)
	}

	pemEncodedPublic, err := EncodePublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, errors.Wrap(
			err,
			"error while encoding public key",
		)
	}

	return pemEncodedPrivate, pemEncodedPublic, nil
}

// EncodePrivateKey encodes a given ECDSA private key to PEM block
func EncodePrivateKey(privateKey *ecdsa.PrivateKey) ([]byte, error) {

	derPrivate, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"error while marshaling ecdsa private key to DER",
		)
	}

	pemEncodedPrivate, err := pemutil.EncodePrivateKey(derPrivate)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"error while encoding private key to PEM",
		)
	}

	return pemEncodedPrivate, nil
}

// EncodePublicKey encodes a given ECDSA public key to PEM block
func EncodePublicKey(publicKey *ecdsa.PublicKey) ([]byte, error) {

	derPublic, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"error while marshaling public key to DER",
		)
	}

	pemEncodedPublic, err := pemutil.EncodePublicKey(derPublic)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"error while encoding public key to PEM",
		)
	}

	return pemEncodedPublic, nil
}

// DecodeKey takes PEM blocks a DER encoded key pair bytes and returns the
// parsed ecdsa.PrivateKey and ecdsa.PublicKey.
func DecodeKey(pemEcodedPrivate []byte, pemEncodedPublic []byte) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {

	privateKey, err := DecodePrivateKey(pemEcodedPrivate)
	if err != nil {
		return nil, nil, err
	}

	publicKey, err := DecodePublicKey(pemEncodedPublic)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

// DecodePrivateKey decodes a PEM block of a DER encoded ecdsa private key
func DecodePrivateKey(pemEncodedPrivate []byte) (*ecdsa.PrivateKey, error) {

	derPrivate, err := pemutil.Decode(pemEncodedPrivate)
	if err != nil {
		return nil, errors.Wrap(err, "error while decoded PEM blocks")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(derPrivate)
	if err != nil {
		return nil, errors.Wrap(err, "error while parsing private key")
	}

	privateKeyECDSA, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrKeyNotECDSA
	}

	return privateKeyECDSA, nil
}

// DecodePublicKey decodes a PEM block of a DER encoded ecdsa private key
func DecodePublicKey(pemEncodedPublic []byte) (*ecdsa.PublicKey, error) {

	derPublic, err := pemutil.Decode(pemEncodedPublic)
	if err != nil {
		return nil, errors.Wrap(err, "error while decoded PEM blocks")
	}

	publicKey, err := x509.ParsePKIXPublicKey(derPublic)
	if err != nil {
		return nil, errors.Wrap(err, "error while parsing private key")
	}

	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, ErrKeyNotECDSA
	}

	return publicKeyECDSA, nil
}
