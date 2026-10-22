package jsruntime

import (
	"container/list"
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/dop251/goja"
)

const scriptName = "mitm-script.js"
const gojaEngineID = "goja"

// CompiledScript is an opaque immutable program tied to the Runtime and
// execution engine that compiled it. It contains no VM state and can be run
// concurrently by that Runtime while it remains open.
type CompiledScript struct {
	program    *goja.Program
	hash       [sha256.Size]byte
	sourceSize int
	runtimeID  uint64
	engineID   string
}

type cacheEntry struct {
	key    [sha256.Size]byte
	script *CompiledScript
}

// programCache keeps compiled programs in a bounded LRU. The map is allocated
// only when the first cache entry is stored.
type programCache struct {
	mu       sync.Mutex
	capacity int
	entries  map[[sha256.Size]byte]*list.Element
	lru      list.List
}

func newProgramCache(capacity int) programCache {
	return programCache{
		capacity: capacity,
	}
}

func (c *programCache) lookup(key [sha256.Size]byte) *CompiledScript {
	c.mu.Lock()
	defer c.mu.Unlock()

	if element, ok := c.entries[key]; ok {
		c.lru.MoveToFront(element)
		return element.Value.(*cacheEntry).script
	}
	return nil
}

// store inserts only while the owning Runtime is open. The closed check is
// made under the same lock used by clear, so Close cannot be followed by a
// cache refill from a compilation already in progress.
func (c *programCache) store(compiled *CompiledScript, closed func() bool) *CompiledScript {
	if c.capacity == 0 {
		return compiled
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if closed() {
		return nil
	}
	if c.entries != nil {
		if element, ok := c.entries[compiled.hash]; ok {
			c.lru.MoveToFront(element)
			return element.Value.(*cacheEntry).script
		}
	}
	if c.entries == nil {
		c.entries = make(map[[sha256.Size]byte]*list.Element)
	}
	element := c.lru.PushFront(&cacheEntry{key: compiled.hash, script: compiled})
	c.entries[compiled.hash] = element
	if c.lru.Len() > c.capacity {
		oldest := c.lru.Back()
		delete(c.entries, oldest.Value.(*cacheEntry).key)
		c.lru.Remove(oldest)
	}
	return compiled
}

func (c *programCache) stats() CacheStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return CacheStats{Entries: len(c.entries), Capacity: c.capacity}
}

func (c *programCache) clear() {
	c.mu.Lock()
	c.entries = nil
	c.lru.Init()
	c.mu.Unlock()
}

func (s *CompiledScript) ContentHash() string {
	if s == nil {
		return ""
	}
	return fmt.Sprintf("%x", s.hash)
}
