package keystore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMemoryStore(t *testing.T) {
	t.Run("OK ECDSA store and retrieve", func(t *testing.T) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		m := NewMemory()
		if err := m.ECDSASetPrivateKey(
			context.Background(),
			"foo",
			k,
		); err != nil {
			t.Fatal(err)
		}

		kk, ok, err := m.ECDSAPrivateKey(
			context.Background(),
			"foo",
		)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatal("should have found ecdsa key with id foo")
		}

		require.Equal(t, k, kk, "key retrieved should be the same as the key stored")
	})
}
