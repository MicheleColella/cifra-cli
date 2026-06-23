package keychain

import "errors"

// Store seals and retrieves private key material in the OS-native secret store.
type Store interface {
	Seal(id string, privateKey []byte) error
	Unseal(id string) ([]byte, error)
	Delete(id string) error
}

// ErrNotAvailable is returned when no keychain backend is present on this system.
var ErrNotAvailable = errors.New("no keychain backend available on this system")

// ErrNotFound is returned when no key exists for the given id.
var ErrNotFound = errors.New("key not found in keychain")

// ErrAlreadyExists is returned by Seal when a key already exists for the given id.
var ErrAlreadyExists = errors.New("key already exists for this id (delete it first to regenerate)")
