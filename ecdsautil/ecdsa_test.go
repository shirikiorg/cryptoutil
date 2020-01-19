package ecdsautil

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestECDSAMethods(t *testing.T) {
	privateKeyPem, publicKeyPem, err := GenerateKeyBytes(
		elliptic.P521(),
		rand.Reader,
	)
	if err != nil {
		t.Fatal(err)
	}

	privateKey, publicKey, err := DecodeKey(
		privateKeyPem,
		publicKeyPem,
	)
	if err != nil {
		t.Fatal(err)
	}

	privateKeyEncoded, publicKeyEncoded, err := EncodeKey(
		privateKey,
		publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	require.Equal(
		t,
		string(privateKeyPem),
		string(privateKeyEncoded),
		"",
	)

	require.Equal(
		t,
		string(publicKeyPem),
		string(publicKeyEncoded),
		"",
	)
}
