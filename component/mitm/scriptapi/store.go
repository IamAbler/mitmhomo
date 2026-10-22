// Package scriptapi contains engine-neutral host services for MITM scripts.
package scriptapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	maxStoreFileBytes = 1 << 20
	maxStoreKeyBytes  = 256
	maxStoreValueSize = 64 << 10
	maxStoreNamespace = 128
	maxStoreEntries   = 512
	maxStoreDirs      = 16
)

var (
	ErrInvalidStoreInput = errors.New("persistent store key, namespace, or value is invalid")
	ErrStoreLimit        = errors.New("persistent store capacity limit exceeded")
	ErrStoreClosed       = errors.New("persistent store is closed")
)

// PersistentStore is safe for concurrent use. Read returns ("", false, nil)
// when a key has not been written.
type PersistentStore interface {
	Read(namespace, key string) (string, bool, error)
	Write(namespace, key, value string) error
}

type Store struct {
	dir    string
	file   string
	shared bool
	mu     sync.Mutex
	loaded bool
	data   map[string]map[string]string
	closed bool
}

var sharedStores = struct {
	sync.Mutex
	items map[string]*Store
}{items: make(map[string]*Store)}

// SharedStore returns a process-shared store for a fixed host-selected
// directory. The registry is bounded so repeated configuration changes cannot
// retain an unlimited number of stores.
func SharedStore(directory string) (*Store, error) {
	if strings.TrimSpace(directory) == "" {
		return nil, errors.New("persistent store directory is empty")
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, fmt.Errorf("resolve persistent store directory: %w", err)
	}
	absolute = filepath.Clean(absolute)
	sharedStores.Lock()
	defer sharedStores.Unlock()
	if existing := sharedStores.items[absolute]; existing != nil {
		return existing, nil
	}
	if len(sharedStores.items) >= maxStoreDirs {
		return nil, ErrStoreLimit
	}
	store := &Store{dir: absolute, file: filepath.Join(absolute, "persistent-store.json"), shared: true, data: make(map[string]map[string]string)}
	sharedStores.items[absolute] = store
	return store, nil
}

// NewStore creates an isolated store, primarily for embedding and tests.
func NewStore(directory string) (*Store, error) {
	if strings.TrimSpace(directory) == "" {
		return nil, errors.New("persistent store directory is empty")
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, fmt.Errorf("resolve persistent store directory: %w", err)
	}
	absolute = filepath.Clean(absolute)
	return &Store{dir: absolute, file: filepath.Join(absolute, "persistent-store.json"), data: make(map[string]map[string]string)}, nil
}

func (s *Store) Read(namespace, key string) (string, bool, error) {
	if err := validateStoreKey(namespace, key); err != nil {
		return "", false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return "", false, err
	}
	value, exists := s.data[namespace][key]
	return value, exists, nil
}

func (s *Store) Write(namespace, key, value string) error {
	if err := validateStoreKey(namespace, key); err != nil || len(value) > maxStoreValueSize {
		return ErrInvalidStoreInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return err
	}
	if old, exists := s.data[namespace][key]; exists && old == value {
		return nil
	}
	candidate := cloneStoreData(s.data)
	if candidate[namespace] == nil {
		candidate[namespace] = make(map[string]string)
	}
	candidate[namespace][key] = value
	encoded, err := json.Marshal(candidate)
	if err != nil {
		return fmt.Errorf("encode persistent store: %w", err)
	}
	if len(encoded) > maxStoreFileBytes || countStoreEntries(candidate) > maxStoreEntries {
		return ErrStoreLimit
	}
	if err := s.writeAtomic(encoded); err != nil {
		return err
	}
	s.data = candidate
	return nil
}

func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	if s.shared {
		// SharedStore and Close use the registry-before-store lock order. The
		// registry entry is removed in the same critical section that marks the
		// instance closed, so a later lookup can never return a closed store.
		sharedStores.Lock()
		s.mu.Lock()
		s.closed = true
		s.data = nil
		if sharedStores.items[s.dir] == s {
			delete(sharedStores.items, s.dir)
		}
		s.mu.Unlock()
		sharedStores.Unlock()
		return nil
	}
	s.mu.Lock()
	s.closed = true
	s.data = nil
	s.mu.Unlock()
	return nil
}

func (s *Store) loadLocked() error {
	if s.closed {
		return ErrStoreClosed
	}
	if s.loaded {
		return nil
	}
	encoded, err := os.ReadFile(s.file)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read persistent store: %w", err)
	}
	if errors.Is(err, os.ErrNotExist) {
		s.loaded = true
		return nil
	}
	if len(encoded) > maxStoreFileBytes {
		return ErrStoreLimit
	}
	var loaded map[string]map[string]string
	if err := json.Unmarshal(encoded, &loaded); err != nil {
		return fmt.Errorf("decode persistent store: %w", err)
	}
	if loaded == nil {
		loaded = make(map[string]map[string]string)
	}
	if countStoreEntries(loaded) > maxStoreEntries {
		return ErrStoreLimit
	}
	for namespace, values := range loaded {
		if err := validateStoreNamespace(namespace); err != nil {
			return ErrInvalidStoreInput
		}
		for key, value := range values {
			if validateStoreKey(namespace, key) != nil || len(value) > maxStoreValueSize {
				return ErrInvalidStoreInput
			}
		}
	}
	s.data = loaded
	s.loaded = true
	return nil
}

func (s *Store) writeAtomic(encoded []byte) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("create persistent store directory: %w", err)
	}
	temporary, err := os.CreateTemp(s.dir, ".persistent-store-*")
	if err != nil {
		return fmt.Errorf("create persistent store temporary file: %w", err)
	}
	name := temporary.Name()
	cleanup := func() { _ = os.Remove(name) }
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		cleanup()
		return fmt.Errorf("set persistent store permissions: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		cleanup()
		return fmt.Errorf("write persistent store: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		cleanup()
		return fmt.Errorf("sync persistent store: %w", err)
	}
	if err := temporary.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close persistent store: %w", err)
	}
	if err := os.Rename(name, s.file); err != nil {
		cleanup()
		return fmt.Errorf("replace persistent store: %w", err)
	}
	if directory, err := os.Open(s.dir); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func validateStoreKey(namespace, key string) error {
	if validateStoreNamespace(namespace) != nil || key == "" || len(key) > maxStoreKeyBytes || strings.IndexByte(key, 0) >= 0 {
		return ErrInvalidStoreInput
	}
	return nil
}

func validateStoreNamespace(namespace string) error {
	if namespace == "" || len(namespace) > maxStoreNamespace || strings.IndexByte(namespace, 0) >= 0 {
		return ErrInvalidStoreInput
	}
	return nil
}

func cloneStoreData(source map[string]map[string]string) map[string]map[string]string {
	cloned := make(map[string]map[string]string, len(source)+1)
	for namespace, values := range source {
		copyValues := make(map[string]string, len(values))
		for key, value := range values {
			copyValues[key] = value
		}
		cloned[namespace] = copyValues
	}
	return cloned
}

func countStoreEntries(data map[string]map[string]string) int {
	count := 0
	for _, values := range data {
		count += len(values)
	}
	return count
}
