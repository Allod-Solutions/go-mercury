package mercury

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
)

// ProcessInfo describes the likely application that produced a TLS fingerprint.
type ProcessInfo struct {
	// Process is the application name, e.g. "firefox", "curl", "python-requests".
	Process string
	// Version is the application version string when available, e.g. "120.0".
	Version string
	// OS is the operating system, e.g. "windows", "linux", "macos".
	OS string
	// Prevalence is the fraction of observations this process accounts for
	// among all processes that produce the same fingerprint (0.0–1.0).
	Prevalence float64
}

// DB holds the Mercury fingerprint database and provides fast lookups.
type DB struct {
	mu      sync.RWMutex
	entries map[string][]ProcessInfo // fingerprint string → ordered candidates
	count   int
}

// NewDB creates an empty DB. Call Load or LoadReader to populate it.
func NewDB() *DB {
	return &DB{entries: make(map[string][]ProcessInfo)}
}

// Load reads the Mercury fingerprint_db.json from path.
func (db *DB) Load(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return db.LoadReader(f)
}

// LoadReader parses the Mercury fingerprint_db.json format from r.
//
// The Mercury fingerprint_db.json is a JSON object where each key is a
// fingerprint string and each value has a "process_info" array:
//
//	{
//	  "<fingerprint>": {
//	    "process_info": [
//	      {"process": "firefox", "prevalence": 0.95,
//	       "os_info": [{"os": "windows", "prevalence": 0.7}]}
//	    ]
//	  }
//	}
func (db *DB) LoadReader(r io.Reader) error {
	// The DB can be large (10+ MB). Decode incrementally via json.Decoder.
	dec := json.NewDecoder(r)

	// Read opening '{'
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return fmt.Errorf("mercury db: expected opening '{': %w", err)
	}

	type osEntry struct {
		OS         string  `json:"os"`
		Prevalence float64 `json:"prevalence"`
	}
	type procEntry struct {
		Process    string    `json:"process"`
		Prevalence float64   `json:"prevalence"`
		OSInfo     []osEntry `json:"os_info"`
	}
	type fpRecord struct {
		ProcessInfo []procEntry `json:"process_info"`
	}

	newEntries := make(map[string][]ProcessInfo)
	for dec.More() {
		// Key = fingerprint string
		keyTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("mercury db: read key: %w", err)
		}
		fp, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("mercury db: expected string key, got %T", keyTok)
		}

		var rec fpRecord
		if err := dec.Decode(&rec); err != nil {
			return fmt.Errorf("mercury db: decode record for %q: %w", fp, err)
		}

		var procs []ProcessInfo
		for _, pe := range rec.ProcessInfo {
			pi := ProcessInfo{
				Process:    pe.Process,
				Prevalence: pe.Prevalence,
			}
			// Pick the most prevalent OS, if any.
			bestOS := ""
			bestOSPrev := 0.0
			for _, oe := range pe.OSInfo {
				if oe.Prevalence > bestOSPrev {
					bestOS = oe.OS
					bestOSPrev = oe.Prevalence
				}
			}
			pi.OS = bestOS
			procs = append(procs, pi)
		}
		if len(procs) > 0 {
			newEntries[fp] = procs
		}
	}

	// Read closing '}'
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("mercury db: read closing '}': %w", err)
	}

	db.mu.Lock()
	db.entries = newEntries
	db.count = len(newEntries)
	db.mu.Unlock()

	slog.Info("mercury: database loaded", "fingerprints", len(newEntries))
	return nil
}

// Lookup returns the best-matching ProcessInfo for the given TLS fingerprint
// string. The caller should pass the output of Fingerprint().
// Returns zero ProcessInfo and false when the fingerprint is not in the DB.
func (db *DB) Lookup(fp string) (ProcessInfo, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	procs, ok := db.entries[fp]
	if !ok || len(procs) == 0 {
		return ProcessInfo{}, false
	}
	return procs[0], true
}

// LookupAll returns all candidate ProcessInfo entries for the fingerprint,
// ordered by decreasing prevalence. Returns nil when not found.
func (db *DB) LookupAll(fp string) []ProcessInfo {
	db.mu.RLock()
	defer db.mu.RUnlock()
	procs := db.entries[fp]
	if len(procs) == 0 {
		return nil
	}
	out := make([]ProcessInfo, len(procs))
	copy(out, procs)
	return out
}

// Count returns the number of fingerprints loaded.
func (db *DB) Count() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.count
}
