// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// CentralSyncWorker periodically replicates unsynced edge ledger records
// to the central PostgreSQL vault via HTTP POST.
type CentralSyncWorker struct {
	centralVaultURL string
	batchSize       int
	syncInterval    time.Duration
	stopChan        chan struct{}
	httpClient      *http.Client
	mu              sync.Mutex
	pendingQueue    []EventRecord
	disabled        bool
}

// NewCentralSyncWorker creates a sync worker targeting the central vault.
// The vault URL is read from the CICADA_VAULT_URL environment variable.
// If unset or empty, sync is disabled (no fallback to localhost).
func NewCentralSyncWorker() *CentralSyncWorker {
	vaultURL := os.Getenv("CICADA_VAULT_URL")
	if vaultURL == "" {
		return &CentralSyncWorker{
			disabled: true,
			stopChan: make(chan struct{}),
		}
	}

	return &CentralSyncWorker{
		centralVaultURL: vaultURL,
		batchSize:       100,
		syncInterval:    10 * time.Second,
		stopChan:        make(chan struct{}),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		pendingQueue: make([]EventRecord, 0),
	}
}

// Enqueue adds a record to the pending sync queue.
func (w *CentralSyncWorker) Enqueue(record EventRecord) {
	if w.disabled {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pendingQueue = append(w.pendingQueue, record)
}

// Start launches the background sync loop.
func (w *CentralSyncWorker) Start() {
	if w.disabled {
		log.Printf("[SYNC] Central vault sync DISABLED — CICADA_VAULT_URL not set")
		return
	}
	log.Printf("[SYNC] Central ledger sync started -> %s (every %v)", w.centralVaultURL, w.syncInterval)
	go func() {
		ticker := time.NewTicker(w.syncInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				w.syncBatch()
			case <-w.stopChan:
				log.Println("[SYNC] Central sync worker stopped")
				return
			}
		}
	}()
}

// Stop halts the sync loop.
func (w *CentralSyncWorker) Stop() {
	close(w.stopChan)
}

func (w *CentralSyncWorker) syncBatch() {
	w.mu.Lock()
	if len(w.pendingQueue) == 0 {
		w.mu.Unlock()
		return
	}

	batch := w.pendingQueue
	if len(batch) > w.batchSize {
		batch = batch[:w.batchSize]
	}
	w.pendingQueue = w.pendingQueue[len(batch):]
	w.mu.Unlock()

	log.Printf("[SYNC] Pushing batch of %d records to central vault...", len(batch))

	hostname, _ := os.Hostname()
	payload, err := json.Marshal(map[string]interface{}{
		"node_id": hostname,
		"records": batch,
	})
	if err != nil {
		log.Printf("[SYNC ERROR] Failed to encode batch: %v", err)
		// Re-enqueue on failure
		w.mu.Lock()
		w.pendingQueue = append(batch, w.pendingQueue...)
		w.mu.Unlock()
		return
	}

	req, err := http.NewRequest("POST", w.centralVaultURL+"/v1/vault/sync/batch", bytes.NewBuffer(payload))
	if err != nil {
		log.Printf("[SYNC ERROR] Failed to create request: %v", err)
		w.requeue(batch)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	// In production, add real auth token from env
	vaultToken := os.Getenv("CICADA_VAULT_TOKEN")
	if vaultToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", vaultToken))
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		log.Printf("[SYNC ERROR] Central vault unreachable: %v", err)
		w.requeue(batch)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("[SYNC] Successfully replicated %d records to central vault", len(batch))
	} else {
		log.Printf("[SYNC ERROR] Central vault returned %d", resp.StatusCode)
		w.requeue(batch)
	}
}

func (w *CentralSyncWorker) requeue(batch []EventRecord) {
	w.mu.Lock()
	w.pendingQueue = append(batch, w.pendingQueue...)
	w.mu.Unlock()
}
