package keystore

import (
	"context"
	"crypto/ecdsa"
	"sync"
	"sync/atomic"
)

type ecdsaMemStore map[string]*ecdsaKeyPair

// Memory is a in memory key store
type Memory struct {
	*ecdsaMem
}

type ecdsaMem struct {
	v  *atomic.Value
	mu *sync.Mutex
}

// NewMemory returns a new in memory key store
func NewMemory() *Memory {
	return &Memory{
		ecdsaMem: newECDSAMem(),
	}
}

func newECDSAMem() *ecdsaMem {
	var v atomic.Value
	s := make(ecdsaMemStore)
	v.Store(s)

	return &ecdsaMem{
		v:  &v,
		mu: &sync.Mutex{},
	}
}

func (e ecdsaMem) ECDSAPrivateKey(_ context.Context, id string) (*ecdsa.PrivateKey, bool, error) {
	s := e.v.Load().(ecdsaMemStore)

	k, ok := s[id]
	if k.PrivateKey == nil {
		return nil, false, nil
	}
	return k.PrivateKey, ok, nil
}

func (e ecdsaMem) ECDSAPublicKey(_ context.Context, id string) (*ecdsa.PublicKey, bool, error) {
	s := e.v.Load().(ecdsaMemStore)

	k, ok := s[id]
	if k.PublicKey == nil {
		return nil, false, nil
	}
	return k.PublicKey, ok, nil
}

func (e ecdsaMem) ECDSASetPrivateKey(_ context.Context, id string, k *ecdsa.PrivateKey) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.v.Load().(ecdsaMemStore)
	ns := make(ecdsaMemStore, len(s))

	for ok, ov := range s {
		ns[ok] = ov
	}
	if v, ok := ns[id]; ok {
		v.PrivateKey = k
	} else {
		ns[id] = &ecdsaKeyPair{
			PrivateKey: k,
			PublicKey:  &k.PublicKey,
		}
	}

	e.v.Store(ns)
	return nil
}

func (e ecdsaMem) ECDSASetPublicKey(_ context.Context, id string, k *ecdsa.PublicKey) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.v.Load().(ecdsaMemStore)
	ns := make(ecdsaMemStore, len(s))

	for ok, ov := range s {
		ns[ok] = ov
	}
	if v, ok := ns[id]; ok {
		v.PublicKey = k
	} else {
		ns[id] = &ecdsaKeyPair{
			PublicKey: k,
		}
	}

	e.v.Store(ns)
	return nil
}
