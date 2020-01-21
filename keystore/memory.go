package keystore

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
)

var ErrKeyNotExist = errors.New("key does not exist in store")

type entry struct {
	key interface{}
}

type store map[string]entry

// Memory is a in memory key store
type Memory struct {
	v  *atomic.Value
	mu *sync.Mutex
}

// NewMemory returns a new in memory key store
func NewMemory() *Memory {
	var v atomic.Value
	v.Store(make(store))

	return &Memory{
		v:  &v,
		mu: &sync.Mutex{},
	}
}

func (m *Memory) GetPKCS8(ctx context.Context, id string) ([]byte, error) {

	k, err := m.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	var pkcs8 []byte

	switch v := k.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey:
		pkcs8, err = x509.MarshalPKIXPublicKey(v)
	case *ecdsa.PrivateKey, *rsa.PrivateKey:
		pkcs8, err = x509.MarshalPKCS8PrivateKey(v)
	}

	if err != nil {
		return nil, err
	}

	return pkcs8, nil
}

func (m *Memory) Get(_ context.Context, id string) (interface{}, error) {

	s := m.v.Load().(store)

	e, ok := s[id]
	if !ok {
		return nil, ErrKeyNotExist
	}

	return e.key, nil
}

func (m *Memory) Set(_ context.Context, id string, k *pem.Block) error {
	// first try to parse the pem blocks
	var key interface{}
	var err error

	if strings.Contains(k.Type, "PUBLIC KEY") {
		key, err = x509.ParsePKIXPublicKey(k.Bytes)
	} else {
		key, err = x509.ParsePKCS8PrivateKey(k.Bytes)
	}
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.v.Load().(store)
	ns := make(store, len(s))

	for ok, ov := range s {
		ns[ok] = ov
	}

	ns[id] = entry{key: key}

	m.v.Store(ns)
	return nil
}
