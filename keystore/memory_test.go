package keystore

import (
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/shirikiorg/cryptoutil/ecdsautil"
	"github.com/stretchr/testify/require"
)

func TestMemoryStore(t *testing.T) {
	t.Run("OK ECDSA store and retrieve", func(t *testing.T) {
		k, _, err := ecdsautil.GenerateKeyPEM(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		pemBlock, _ := pem.Decode(k)

		m := NewMemory()
		if err := m.Set(
			context.Background(),
			"foo",
			pemBlock,
		); err != nil {
			t.Fatal(err)
		}

		kk, err := m.Get(
			context.Background(),
			"foo",
		)

		if err != nil {
			t.Fatal(err)
		}

		der, _ := x509.MarshalPKCS8PrivateKey(kk)
		blk := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		})

		require.Equal(t, string(k), string(blk), "key retrieved should be the same as the key stored")
	})
}
