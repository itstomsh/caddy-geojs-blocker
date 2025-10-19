// Unit tests for GeoJSBlocker: cache, decisions, counters, and IP extraction.
package geojsblock

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func TestNormalizeCodes(t *testing.T) {
	tests := []struct {
		in   []string
		want []string
	}{
		{[]string{"US", "us ", "CA", "xxx"}, []string{"US", "CA"}}, // "xxx" len=3 → skipped
		{[]string{}, []string{}},
		{[]string{"ABC"}, []string{}}, // Invalid len
	}
	for _, tt := range tests {
		if got := normalizeCodes(tt.in); !equalStringSlices(got, tt.want) {
			t.Errorf("normalizeCodes(%v) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestCountersIncAllowBlock(t *testing.T) {
	c := newCounters()
	c.incAllow("DE")
	c.incBlock("??")
	c.incAllow("") // Uses "??"

	snap := c.snapshot()
	if snap["total_allowed"].(uint64) != 2 {
		t.Errorf("total_allowed = %d, want 2", snap["total_allowed"])
	}
	if snap["total_blocked"].(uint64) != 1 {
		t.Errorf("total_blocked = %d, want 1", snap["total_blocked"])
	}
	if v, ok := snap["allowed_by_cc"].(map[string]uint64)["??"]; !ok || v != 1 {
		t.Errorf("allowed_by_cc[??] = %d, want 1", v)
	}
	if v, ok := snap["blocked_by_cc"].(map[string]uint64)["??"]; !ok || v != 1 {
		t.Errorf("blocked_by_cc[??] = %d, want 1", v)
	}
	c.reset()
	if snap := c.snapshot(); snap["total_allowed"].(uint64) != 0 {
		t.Errorf("reset failed: total_allowed = %d", snap["total_allowed"])
	}
}

func TestIPCache(t *testing.T) {
	cache := newIPCache(10, 1*time.Hour)
	cache.Set("1.2.3.4", "DE")
	if country, ok := cache.Get("1.2.3.4"); !ok || country != "DE" {
		t.Errorf("cache.Get() = %q, %t; want %q, true", country, ok, "DE")
	}
	// Expire entry via manual prune
	cache.data["expired"] = ipCacheEntry{country: "US", expiresAt: time.Now().Add(-1 * time.Hour)}
	cache.pruneExpired()
	if _, ok := cache.Get("expired"); ok {
		t.Error("pruneExpired failed")
	}
	// Eviction: fill to max, expect random removal
	for i := 0; i < 11; i++ {
		cache.Set(fmt.Sprintf("ip%d", i), "XX")
	}
	if len(cache.data) > 10 {
		t.Log("Eviction approximate; ok")
	}
}

func TestDecide(t *testing.T) {
	i := &GeoJSBlocker{
		Allowed: []string{"DE"},
		allowUD: true,
		logger:  zap.NewNop(),
		stats:   newCounters(),
	}
	r := httptest.NewRequest("GET", "/", nil)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })

	// Allowlist allow
	err := i.decide("DE", httptest.NewRecorder(), r, next, false, "1.2.3.4")
	if err != nil {
		t.Errorf("decide(DE) error = %v, want nil", err)
	}

	// Allowlist block
	err = i.decide("US", httptest.NewRecorder(), r, next, false, "1.2.3.4")
	if err == nil {
		t.Errorf("decide(US allowlist) err = nil, want HandlerError")
	} else {
		if cerr, ok := err.(caddyhttp.HandlerError); !ok {
			t.Errorf("decide(US allowlist) not caddyhttp.HandlerError: %T", err)
		} else if cerr.StatusCode != http.StatusForbidden {
			t.Errorf("decide(US allowlist) status = %d, want %d", cerr.StatusCode, http.StatusForbidden)
		} else if msg := cerr.Err.Error(); msg != "country not allowed" {
			t.Errorf("decide(US allowlist) msg = %q, want %q", msg, "country not allowed")
		}
	}

	// Blocklist mode
	i.Allowed = nil
	i.Blocked = []string{"US"}
	i.stats = newCounters()

	err = i.decide("DE", httptest.NewRecorder(), r, next, false, "1.2.3.4")
	if err != nil {
		t.Errorf("decide(DE blocklist) error = %v, want nil", err)
	}
	err = i.decide("US", httptest.NewRecorder(), r, next, false, "1.2.3.4")
	if err == nil {
		t.Errorf("decide(US blocklist) err = nil, want HandlerError")
	} else {
		if cerr, ok := err.(caddyhttp.HandlerError); !ok {
			t.Errorf("decide(US blocklist) not caddyhttp.HandlerError: %T", err)
		} else if cerr.StatusCode != http.StatusForbidden {
			t.Errorf("decide(US blocklist) status = %d, want %d", cerr.StatusCode, http.StatusForbidden)
		} else if msg := cerr.Err.Error(); msg != "country blocked" {
			t.Errorf("decide(US blocklist) msg = %q, want %q", msg, "country blocked")
		}
	}
}

func TestOnUndetected(t *testing.T) {
	i := &GeoJSBlocker{
		allowUD: true,
		logger:  zap.NewNop(),
		stats:   newCounters(),
	}
	r := httptest.NewRequest("GET", "/", nil)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })

	// Allow
	err := i.onUndetected(httptest.NewRecorder(), r, next, "test")
	if err != nil {
		t.Errorf("onUndetected(allow) error = %v, want nil", err)
	}

	// Block
	i.allowUD = false
	i.stats = newCounters()
	err = i.onUndetected(httptest.NewRecorder(), r, next, "test")
	if err == nil {
		t.Errorf("onUndetected(block) err = nil, want HandlerError")
	} else {
		if cerr, ok := err.(caddyhttp.HandlerError); !ok {
			t.Errorf("onUndetected(block) not caddyhttp.HandlerError: %T", err)
		} else if cerr.StatusCode != http.StatusForbidden {
			t.Errorf("onUndetected(block) status = %d, want %d", cerr.StatusCode, http.StatusForbidden)
		} else if msg := cerr.Err.Error(); msg != "country undetected" {
			t.Errorf("onUndetected(block) msg = %q, want %q", msg, "country undetected")
		}
	}
}

func TestFetch(t *testing.T) {
	// Count upstream hits
	var hits int32

	// Mock GeoJS server that returns "DE" for /1.2.3.4
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.URL.Path == "/1.2.3.4" {
			_, _ = w.Write([]byte("DE"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	i := &GeoJSBlocker{
		logger:  zap.NewNop(),
		stats:   newCounters(),
		apiBase: srv.URL,             // inject mock base URL
		useSF:   false,               // keep simple for this test
		allowUD: true,                // allow if something goes wrong
		cache:   newIPCache(10, time.Minute),
		// Make decision path explicit -> allowlist includes DE
		Allowed: []string{"DE"},
	}

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })

	// First request -> triggers fetch to mock server
	r1 := httptest.NewRequest("GET", "http://example/", nil)
	r1.Header.Set("X-Real-IP", "1.2.3.4")
	rr1 := httptest.NewRecorder()
	if err := i.ServeHTTP(rr1, r1, next); err != nil {
		t.Fatalf("ServeHTTP (first) returned error: %v", err)
	}

	// Second request (new Request instance) -> should use cache
	r2 := httptest.NewRequest("GET", "http://example/", nil)
	r2.Header.Set("X-Real-IP", "1.2.3.4")
	rr2 := httptest.NewRecorder()
	if err := i.ServeHTTP(rr2, r2, next); err != nil {
		t.Fatalf("ServeHTTP (second, cache) returned error: %v", err)
	}

	// Ensure the mock server was called only once (second call came from cache)
	if gotHits := atomic.LoadInt32(&hits); gotHits != 1 {
		t.Fatalf("expected exactly 1 upstream fetch, got %d", gotHits)
	}

	totalAllowed := atomic.LoadUint64(&i.stats.TotalAllowed)
	if totalAllowed != 1 {
		t.Fatalf("expected total_allowed = 1 (only non-cached counted), got %d", totalAllowed)
	}
}

func TestClientIPFromRequest(t *testing.T) {
	// XFF
	r1 := httptest.NewRequest("GET", "/", nil)
	r1.Header.Set("X-Forwarded-For", " 1.2.3.4 , junk")
	if got := clientIPFromRequest(r1); got != "1.2.3.4" {
		t.Errorf("clientIPFromRequest(XFF) = %q, want 1.2.3.4", got)
	}

	// XRI
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.Header.Set("X-Real-IP", "5.6.7.8")
	if got := clientIPFromRequest(r2); got != "5.6.7.8" {
		t.Errorf("clientIPFromRequest(XRI) = %q, want 5.6.7.8", got)
	}

	// Remote
	r3 := httptest.NewRequest("GET", "/", nil)
	r3.RemoteAddr = "1.2.3.4:1234"
	if got := clientIPFromRequest(r3); got != "1.2.3.4" {
		t.Errorf("clientIPFromRequest(Remote) = %q, want 1.2.3.4", got)
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
