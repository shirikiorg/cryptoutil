package ecdsautil

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestECDSAMethods(t *testing.T) {
	privateKeyPem, publicKeyPem, err := GenerateKeyPairBytes(
		elliptic.P521(),
		rand.Reader,
	)
	if err != nil {
		t.Fatal(err)
	}

	privateKey, publicKey, err := DecodeKeyPairBytes(
		privateKeyPem,
		publicKeyPem,
	)
	if err != nil {
		t.Fatal(err)
	}

	privateKeyEncoded, publicKeyEncoded, err := EncodeKeyPair(
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
