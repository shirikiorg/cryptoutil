package ecdsautil

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestECDSAMethods(t *testing.T) {
	privateKeyPem, _, err := GenerateKeyPEM(
		elliptic.P521(),
		rand.Reader,
	)
	if err != nil {
		t.Fatal(err)
	}

	privateKey, err := DecodePrivateKey(
		privateKeyPem,
	)
	if err != nil {
		t.Fatal(err)
	}

	privateKeyEncoded, err := EncodePrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	require.Equal(
		t,
		string(privateKeyPem),
		string(privateKeyEncoded),
		"",
	)
}
