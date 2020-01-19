package keystore

import (
	"context"
	"crypto/ecdsa"
)

// ECDSAStore is a store for ECDSA keys
type ECDSAStore interface {
	ECDSAPrivateKey(ctx context.Context, id string) (*ecdsa.PrivateKey, bool, error)
	ECDSAPublicKey(ctx context.Context, id string) (*ecdsa.PublicKey, bool, error)
	ECDSASetPrivateKey(ctx context.Context, id string, k *ecdsa.PrivateKey) error
	ECSASetPublicKey(ctx context.Context, id string, k *ecdsa.PrivateKey) error
}

// ecdsaKeyPair are elements in the ECDSA store
type ecdsaKeyPair struct {
	PublicKey  *ecdsa.PublicKey
	PrivateKey *ecdsa.PrivateKey
}
