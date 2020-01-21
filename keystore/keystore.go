package keystore

import (
	"context"
	"encoding/pem"
)

// KeyStore is an interface of a storage for keys
type KeyStore interface {
	GetPKCS8(ctx context.Context, id string) ([]byte, error)
	Get(ctx context.Context, id string) (interface{}, error)
	Set(ctx context.Context, id string, key *pem.Block) error
}
