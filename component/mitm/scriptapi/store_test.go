package scriptapi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/mitm/scripthost"
)

func TestPersistentStoreReadWriteNamespaceAndReload(t *testing.T) {
	directory := t.TempDir()
	store, err := NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if value, exists, err := store.Read("rule-a", "token"); err != nil || exists || value != "" {
		t.Fatalf("missing Read() = %q, %t, %v", value, exists, err)
	}
	if err := store.Write("rule-a", "token", "one"); err != nil {
		t.Fatal(err)
	}
	if err := store.Write("rule-b", "token", "two"); err != nil {
		t.Fatal(err)
	}
	if value, exists, err := store.Read("rule-a", "token"); err != nil || !exists || value != "one" {
		t.Fatalf("Read(rule-a) = %q, %t, %v", value, exists, err)
	}

	reloaded, err := NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if value, exists, err := reloaded.Read("rule-b", "token"); err != nil || !exists || value != "two" {
		t.Fatalf("reloaded Read() = %q, %t, %v", value, exists, err)
	}
}

func TestPersistentStoreDoesNotWriteUnchangedValue(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write("rule", "key", "value"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.dir, "persistent-store.json")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if err := store.Write("rule", "key", "value"); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() {
		t.Fatalf("unchanged value rewrote the store: before=%v/%d after=%v/%d", before.ModTime(), before.Size(), after.ModTime(), after.Size())
	}
}

func TestPersistentStoreConcurrentWritesAndCapacity(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const workers = 32
	var wait sync.WaitGroup
	errCh := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			key := strings.Repeat("k", 1) + string(rune('a'+index))
			errCh <- store.Write("concurrent", key, "value")
		}(index)
	}
	wait.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}

	for index := 0; index < 15; index++ {
		if err := store.Write("large", fmt.Sprintf("payload-%d", index), strings.Repeat("x", maxStoreValueSize)); err != nil {
			t.Fatalf("large write %d failed before capacity: %v", index, err)
		}
	}
	if err := store.Write("large", "payload-over-limit", strings.Repeat("y", maxStoreValueSize)); !errors.Is(err, ErrStoreLimit) {
		t.Fatalf("total capacity error = %v, want ErrStoreLimit", err)
	}
	if err := store.Write("large", "too-long", strings.Repeat("x", maxStoreValueSize+1)); !errors.Is(err, ErrInvalidStoreInput) {
		t.Fatalf("value size error = %v, want ErrInvalidStoreInput", err)
	}
}

func TestPersistentStoreConcurrentSameKeyReadsAndWrites(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const workers = 24
	start := make(chan struct{})
	var wait sync.WaitGroup
	errCh := make(chan error, workers*2)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			errCh <- store.Write("same-rule", "same-key", strconv.Itoa(index))
		}(index)
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, _, readErr := store.Read("same-rule", "same-key")
			errCh <- readErr
		}()
	}
	close(start)
	wait.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	value, exists, err := store.Read("same-rule", "same-key")
	if err != nil || !exists {
		t.Fatalf("final same-key Read() = %q, %t, %v", value, exists, err)
	}
	if _, err := strconv.Atoi(value); err != nil {
		t.Fatalf("final same-key value %q is not one of the committed values", value)
	}
}

func TestPersistentStoreValidationAndWriteFailure(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write("rule", "", "value"); !errors.Is(err, ErrInvalidStoreInput) {
		t.Fatalf("empty key error = %v, want ErrInvalidStoreInput", err)
	}
	if err := store.Write("rule", "key", strings.Repeat("x", maxStoreValueSize+1)); !errors.Is(err, ErrInvalidStoreInput) {
		t.Fatalf("oversized value error = %v, want ErrInvalidStoreInput", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Read("rule", "key"); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("closed Read() error = %v, want ErrStoreClosed", err)
	}

	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	failing, err := NewStore(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := failing.Write("rule", "key", "value"); err == nil {
		t.Fatal("Write() succeeded below a regular file path")
	}
}

func TestPersistentStoreRejectsInvalidPersistedNamespace(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "persistent-store.json")
	if err := os.WriteFile(path, []byte(`{"":{"unused":"value"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Read("rule", "key"); !errors.Is(err, ErrInvalidStoreInput) {
		t.Fatalf("Read() error = %v, want ErrInvalidStoreInput", err)
	}
}

func TestSharedPersistentStoreReturnsSameGenerationStore(t *testing.T) {
	directory := t.TempDir()
	one, err := SharedStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = one.Close() })
	two, err := SharedStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if one != two {
		t.Fatal("configuration reload created an independent in-memory store")
	}
}

func TestSharedPersistentStoreSurvivesHostGenerationChanges(t *testing.T) {
	directory := t.TempDir()
	store, err := SharedStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	oldHost, err := NewHost(HostConfig{Namespace: "shared-rule", Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if value, err := oldHost.Call(context.Background(), nil, scripthost.HostCall{Name: "$persistentStore.write", Args: []any{"before-reload", "key"}}); err != nil || value != true {
		t.Fatalf("old Host persistent write = %#v, %v", value, err)
	}
	oldHost.Close()

	expected := "before-reload"
	for generation := 0; generation < 32; generation++ {
		reloaded, err := SharedStore(directory)
		if err != nil {
			t.Fatalf("generation %d SharedStore(): %v", generation, err)
		}
		if reloaded != store {
			t.Fatalf("generation %d returned a different live store", generation)
		}
		newHost, err := NewHost(HostConfig{Namespace: "shared-rule", Store: reloaded})
		if err != nil {
			t.Fatal(err)
		}
		if value, err := newHost.Call(context.Background(), nil, scripthost.HostCall{Name: "$persistentStore.read", Args: []any{"key"}}); err != nil || value != expected {
			t.Fatalf("generation %d persistent read = %#v, %v", generation, value, err)
		}
		if value, err := newHost.Call(context.Background(), nil, scripthost.HostCall{Name: "$persistentStore.write", Args: []any{strconv.Itoa(generation), "key"}}); err != nil || value != true {
			t.Fatalf("generation %d persistent write = %#v, %v", generation, value, err)
		}
		expected = strconv.Itoa(generation)
		newHost.Close()
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second shared Store.Close() = %v", err)
	}
	reloaded, err := SharedStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded == store {
		t.Fatal("SharedStore returned a closed store after reacquisition")
	}
	if value, exists, err := reloaded.Read("shared-rule", "key"); err != nil || !exists || value != "31" {
		t.Fatalf("reopened persisted value = %q, %t, %v", value, exists, err)
	}
	if err := reloaded.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSharedStoreCloseRacesWithReacquisition(t *testing.T) {
	directory := t.TempDir()
	store, err := SharedStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write("rule", "key", "persisted"); err != nil {
		t.Fatal(err)
	}
	const readers = 16
	start := make(chan struct{})
	var wait sync.WaitGroup
	errCh := make(chan error, readers+1)
	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		errCh <- store.Close()
	}()
	for index := 0; index < readers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			acquired, acquireErr := SharedStore(directory)
			if acquireErr != nil {
				errCh <- acquireErr
				return
			}
			if acquired != store {
				if _, _, readErr := acquired.Read("rule", "key"); readErr != nil {
					errCh <- readErr
					return
				}
			}
			errCh <- nil
		}()
	}
	close(start)
	wait.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	current, err := SharedStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if current == store || current.closed {
		t.Fatal("registry retained or returned the closed store")
	}
	if err := current.Write("rule", "key", "reopened"); err != nil {
		t.Fatalf("write through reacquired store = %v", err)
	}
	if err := current.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSharedStoreRegistryCapacityIsBounded(t *testing.T) {
	directory := t.TempDir()
	stores := make([]*Store, 0, maxStoreDirs)
	for index := 0; index < maxStoreDirs; index++ {
		store, err := SharedStore(filepath.Join(directory, strconv.Itoa(index)))
		if err != nil {
			t.Fatalf("SharedStore(%d) = %v, want success within capacity", index, err)
		}
		stores = append(stores, store)
	}
	if _, err := SharedStore(filepath.Join(directory, "over-capacity")); !errors.Is(err, ErrStoreLimit) {
		t.Fatalf("over-capacity SharedStore() error = %v, want ErrStoreLimit", err)
	}
	for _, store := range stores {
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
