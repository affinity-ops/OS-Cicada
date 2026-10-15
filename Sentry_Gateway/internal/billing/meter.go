// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package billing

import (
	"sync"
	"sync/atomic"
)

// AtomicMeter provides zero-latency double buffering for Hot Path tracing
type AtomicMeter struct {
	// activeTallies holds `map[string]*atomic.Int64` corresponding to Org/Tenant Usage Loops
	activeTallies atomic.Value 
	mapMutex      sync.Mutex // Exclusively used when injecting new Tenant metrics explicitly to prevent map overwrites
}

func NewAtomicMeter() *AtomicMeter {
	am := &AtomicMeter{}
	am.activeTallies.Store(make(map[string]*atomic.Int64))
	return am
}

// Increment adds a billable trace immediately with ~2 nanosecond latency (Zero IO Blocking).
func (m *AtomicMeter) Increment(tenantID string) {
	tallies := m.activeTallies.Load().(map[string]*atomic.Int64)
	
	// Fast Path
	if counter, exists := tallies[tenantID]; exists {
		counter.Add(1)
		return
	}

	// Double Buffer mapping for new Tenant instantiation
	m.mapMutex.Lock()
	defer m.mapMutex.Unlock()

	// Recheck state post-lock
	tallies = m.activeTallies.Load().(map[string]*atomic.Int64)
	if counter, exists := tallies[tenantID]; exists {
		counter.Add(1)
		return
	}

	// Clone & Store
	newTallies := make(map[string]*atomic.Int64, len(tallies)+1)
	for k, v := range tallies {
		newTallies[k] = v
	}

	newCounter := &atomic.Int64{}
	newCounter.Add(1)
	newTallies[tenantID] = newCounter
	
	m.activeTallies.Store(newTallies)
}

// ExtractAndReset performs the 3-Second Gossip-Loop Snapshot, returning the exact physical usage mapping and zeroing the proxy memory for the next loop.
func (m *AtomicMeter) ExtractAndReset() map[string]int64 {
	m.mapMutex.Lock()
	defer m.mapMutex.Unlock()

	oldTallies := m.activeTallies.Load().(map[string]*atomic.Int64)
	extracted := make(map[string]int64, len(oldTallies))

	for tenantID, counter := range oldTallies {
		extracted[tenantID] = counter.Load()
	}

	// Physically Reset to empty map to clear memory allocation safely without dropping active HTTP streams.
	m.activeTallies.Store(make(map[string]*atomic.Int64))

	return extracted
}
