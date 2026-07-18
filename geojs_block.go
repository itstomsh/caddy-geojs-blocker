package geojsblock

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// Per-instance cache

type ipCacheEntry struct {
	country   string
	expiresAt time.Time
}

type ipCache struct {
	mu         sync.RWMutex
	data       map[string]ipCacheEntry
	maxEntries int
	ttl        time.Duration
}

func newIPCache(maxEntries int, ttl time.Duration) *ipCache {
	return &ipCache{
		data:       make(map[string]ipCacheEntry, maxEntries/2),
		maxEntries: maxEntries,
		ttl:        ttl,
	}
}

func (c *ipCache) Get(ip string) (string, bool) {
	now := time.Now()
	c.mu.RLock()
	e, ok := c.data[ip]
	c.mu.RUnlock()
	if !ok || now.After(e.expiresAt) {
		if ok {
			c.mu.Lock()
			delete(c.data, ip)
			c.mu.Unlock()
		}
		return "", false
	}
	return e.country, true
}

func (c *ipCache) Set(ip, country string) {
	now := time.Now()
	c.mu.Lock()
	if c.maxEntries > 0 && len(c.data) >= c.maxEntries {
		n := c.maxEntries/100 + 1
		for k := range c.data {
			delete(c.data, k)
			n--
			if n <= 0 {
				break
			}
		}
	}
	c.data[ip] = ipCacheEntry{country: country, expiresAt: now.Add(c.ttl)}
	c.mu.Unlock()
}

func (c *ipCache) pruneExpired() {
	now := time.Now()
	c.mu.Lock()
	for k, v := range c.data {
		if now.After(v.expiresAt) {
			delete(c.data, k)
		}
	}
	c.mu.Unlock()
}

// Debug counters

type counters struct {
	mu             sync.Mutex
	ByCountryBlock map[string]uint64
	ByCountryAllow map[string]uint64
	TotalBlocked   uint64
	TotalAllowed   uint64
	CacheHits      uint64 // requests resolved from the IP cache, no GeoJS call made
	ApiCalls       uint64 // physical GeoJS API calls (singleflight collapses concurrent duplicates into one)
	ApiErrors      uint64 // subset of ApiCalls that failed (network error, bad status, invalid country)
}

func newCounters() *counters {
	return &counters{
		ByCountryBlock: make(map[string]uint64),
		ByCountryAllow: make(map[string]uint64),
	}
}

func (c *counters) incBlock(country string) {
	if country == "" {
		country = "??"
	}
	c.mu.Lock()
	c.ByCountryBlock[country]++
	c.mu.Unlock()
	atomic.AddUint64(&c.TotalBlocked, 1)
}

func (c *counters) incAllow(country string) {
	if country == "" {
		country = "??"
	}
	c.mu.Lock()
	c.ByCountryAllow[country]++
	c.mu.Unlock()
	atomic.AddUint64(&c.TotalAllowed, 1)
}

func (c *counters) incCacheHit() {
	atomic.AddUint64(&c.CacheHits, 1)
}

func (c *counters) incApiCall() {
	atomic.AddUint64(&c.ApiCalls, 1)
}

func (c *counters) incApiError() {
	atomic.AddUint64(&c.ApiErrors, 1)
}

func (c *counters) snapshot() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	// shallow copies so JSON can’t race
	blockCopy := make(map[string]uint64, len(c.ByCountryBlock))
	for k, v := range c.ByCountryBlock {
		blockCopy[k] = v
	}
	allowCopy := make(map[string]uint64, len(c.ByCountryAllow))
	for k, v := range c.ByCountryAllow {
		allowCopy[k] = v
	}
	return map[string]any{
		"total_blocked": atomic.LoadUint64(&c.TotalBlocked),
		"total_allowed": atomic.LoadUint64(&c.TotalAllowed),
		"blocked_by_cc": blockCopy,
		"allowed_by_cc": allowCopy,
		"cache_hits":    atomic.LoadUint64(&c.CacheHits),
		"api_calls":     atomic.LoadUint64(&c.ApiCalls),
		"api_errors":    atomic.LoadUint64(&c.ApiErrors),
	}
}

func (c *counters) reset() {
	c.mu.Lock()
	c.ByCountryBlock = make(map[string]uint64)
	c.ByCountryAllow = make(map[string]uint64)
	c.mu.Unlock()
	atomic.StoreUint64(&c.TotalBlocked, 0)
	atomic.StoreUint64(&c.TotalAllowed, 0)
	atomic.StoreUint64(&c.CacheHits, 0)
	atomic.StoreUint64(&c.ApiCalls, 0)
	atomic.StoreUint64(&c.ApiErrors, 0)
}

// countersSnapshot mirrors the debug endpoint's JSON shape and is the
// on-disk format used to persist counters across restarts/reloads.
type countersSnapshot struct {
	TotalBlocked   uint64            `json:"total_blocked"`
	TotalAllowed   uint64            `json:"total_allowed"`
	ByCountryBlock map[string]uint64 `json:"blocked_by_cc"`
	ByCountryAllow map[string]uint64 `json:"allowed_by_cc"`
	CacheHits      uint64            `json:"cache_hits"`
	ApiCalls       uint64            `json:"api_calls"`
	ApiErrors      uint64            `json:"api_errors"`
}

// saveCountersToFile writes counters to path as JSON, via a temp file +
// rename so a crash mid-write can't leave a truncated/corrupt file.
func saveCountersToFile(path string, c *counters) error {
	snap := c.snapshot()
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// loadCountersFromFile reads a previously saved snapshot. A missing file
// is reported via the returned error (check with os.IsNotExist) so the
// caller can fall back to a fresh, empty counters set.
func loadCountersFromFile(path string) (*counters, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s countersSnapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	c := newCounters()
	if s.ByCountryBlock != nil {
		c.ByCountryBlock = s.ByCountryBlock
	}
	if s.ByCountryAllow != nil {
		c.ByCountryAllow = s.ByCountryAllow
	}
	c.TotalBlocked = s.TotalBlocked
	c.TotalAllowed = s.TotalAllowed
	c.CacheHits = s.CacheHits
	c.ApiCalls = s.ApiCalls
	c.ApiErrors = s.ApiErrors
	return c, nil
}

// GeoJSBlocker is a Caddy HTTP handler that filters requests based on GeoJS country lookup.
// It enforces an allowlist or blocklist and maintains cache, counters, and a debug endpoint.
type GeoJSBlocker struct {
	Blocked []string `json:"blocked_countries,omitempty"`
	Allowed []string `json:"allowed_countries,omitempty"`

	CacheTTL        string `json:"cache_ttl,omitempty"`
	CacheSize       int    `json:"cache_size,omitempty"`
	PruneInterval   string `json:"prune_interval,omitempty"`
	Singleflight    string `json:"singleflight,omitempty"`
	AllowUndetected string `json:"allow_undetected,omitempty"`

	DebugPath  string `json:"debug_path,omitempty"`
	DebugToken string `json:"debug_token,omitempty"`

	StatsFile          string `json:"stats_file,omitempty"`
	StatsFlushInterval string `json:"stats_flush_interval,omitempty"`

	cache       *ipCache
	sfGroup     *singleflight.Group
	useSF       bool
	allowUD     bool
	logger      *zap.Logger
	stats       *counters
	statsFileMu *sync.Mutex // serializes stats_file writes (periodic flush vs. reset vs. cleanup)
	apiBase     string
	stopCh      chan struct{}
}

func (GeoJSBlocker) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.geojs_block",
		New: func() caddy.Module { return new(GeoJSBlocker) },
	}
}

var httpClient = &http.Client{Timeout: 2 * time.Second}

func normalizeCodes(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		code := strings.ToUpper(strings.TrimSpace(v))
		if len(code) != 2 {
			continue
		}
		if _, dup := seen[code]; !dup {
			seen[code] = struct{}{}
			out = append(out, code)
		}
	}
	return out
}

func (i *GeoJSBlocker) Provision(ctx caddy.Context) error {
	i.logger = ctx.Logger(i)
	i.DebugPath = strings.TrimSpace(i.DebugPath)

	i.Blocked = normalizeCodes(i.Blocked)
	i.Allowed = normalizeCodes(i.Allowed)

	ttl := 15 * time.Minute
	if i.CacheTTL != "" {
		if d, err := time.ParseDuration(i.CacheTTL); err == nil && d > 0 {
			ttl = d
		} else {
			i.logger.Warn("invalid cache_ttl; using default", zap.String("cache_ttl", i.CacheTTL), zap.Duration("default", ttl))
		}
	}
	size := 50000
	if i.CacheSize > 0 {
		size = i.CacheSize
	}

	i.useSF = true
	switch strings.ToLower(strings.TrimSpace(i.Singleflight)) {
	case "", "on", "true", "1", "yes":
		i.useSF = true
	case "off", "false", "0", "no":
		i.useSF = false
	default:
		if i.Singleflight != "" {
			i.logger.Warn("invalid singleflight; using default 'on'", zap.String("singleflight", i.Singleflight))
		}
	}

	i.allowUD = true
	switch strings.ToLower(strings.TrimSpace(i.AllowUndetected)) {
	case "", "on", "true", "1", "yes":
		i.allowUD = true
	case "off", "false", "0", "no":
		i.allowUD = false
	default:
		if i.AllowUndetected != "" {
			i.logger.Warn("invalid allow_undetected; using default 'on'", zap.String("allow_undetected", i.AllowUndetected))
		}
	}

	pruneDur := 5 * time.Minute
	if i.PruneInterval != "" {
		if d, err := time.ParseDuration(i.PruneInterval); err == nil && d > 0 {
			pruneDur = d
		} else {
			i.logger.Warn("invalid prune_interval; using default", zap.String("prune_interval", i.PruneInterval), zap.Duration("default", pruneDur))
		}
	}

	// defaults to pruneDur unless overridden, so existing configs keep their
	// current flush cadence without needing to set anything new
	statsFlushDur := pruneDur
	if i.StatsFlushInterval != "" {
		if d, err := time.ParseDuration(i.StatsFlushInterval); err == nil && d > 0 {
			statsFlushDur = d
		} else {
			i.logger.Warn("invalid stats_flush_interval; using default", zap.String("stats_flush_interval", i.StatsFlushInterval), zap.Duration("default", statsFlushDur))
		}
	}

	// counters, optionally seeded from a prior snapshot on disk
	i.stats = newCounters()
	i.statsFileMu = new(sync.Mutex)
	i.StatsFile = strings.TrimSpace(i.StatsFile)
	if i.StatsFile != "" {
		if loaded, err := loadCountersFromFile(i.StatsFile); err == nil {
			i.stats = loaded
		} else if !os.IsNotExist(err) {
			i.logger.Warn("failed to load stats_file; starting with empty stats",
				zap.String("stats_file", i.StatsFile), zap.Error(err))
		}
	}

	// per-instance cache + pruner
	i.cache = newIPCache(size, ttl)
	i.sfGroup = new(singleflight.Group)
	i.stopCh = make(chan struct{})

	go func() {
		pruneTicker := time.NewTicker(pruneDur)
		defer pruneTicker.Stop()

		// only ticks if stats_file is configured; a nil channel blocks
		// forever in select, so this case is simply never taken otherwise
		var statsTickerC <-chan time.Time
		if i.StatsFile != "" {
			statsTicker := time.NewTicker(statsFlushDur)
			defer statsTicker.Stop()
			statsTickerC = statsTicker.C
		}

		for {
			select {
			case <-pruneTicker.C:
				i.cache.pruneExpired()
			case <-statsTickerC:
				i.flushStatsFile("periodic")
			case <-i.stopCh:
				return
			}
		}
	}()

	// default API base (kept private; tests can override)
	if strings.TrimSpace(i.apiBase) == "" {
		i.apiBase = "https://get.geojs.io/v1/ip/country"
	}

	i.logger.Info("geojs_block initialized",
		zap.Strings("blocked", i.Blocked),
		zap.Strings("allowed", i.Allowed),
		zap.Duration("cache_ttl", ttl),
		zap.Int("cache_size", size),
		zap.Duration("prune_interval", pruneDur),
		zap.Duration("stats_flush_interval", statsFlushDur),
		zap.Bool("singleflight", i.useSF),
		zap.Bool("allow_undetected", i.allowUD),
		zap.String("debug_path", i.DebugPath),
		zap.String("stats_file", i.StatsFile),
	)

	return nil
}

func (i *GeoJSBlocker) Validate() error {
	if len(i.Blocked) > 0 && len(i.Allowed) > 0 {
		return errors.New("geojs_block: both Blocked and Allowed are set; use only one")
	}
	return nil
}

// Cleanup stops the background cache pruner and persists a final stats
// snapshot (if stats_file is set) when the module is unloaded or replaced.
func (i *GeoJSBlocker) Cleanup() error {
	if i.stopCh != nil {
		close(i.stopCh)
		i.stopCh = nil
	}
	i.flushStatsFile("cleanup")
	return nil
}

// flushStatsFile persists the current counters to StatsFile, if configured.
// Writes are serialized via statsFileMu so the periodic ticker, a debug
// reset, and Cleanup can never race on the same temp file.
func (i *GeoJSBlocker) flushStatsFile(stage string) {
	if i.StatsFile == "" || i.stats == nil {
		return
	}
	i.statsFileMu.Lock()
	defer i.statsFileMu.Unlock()
	if err := saveCountersToFile(i.StatsFile, i.stats); err != nil {
		i.logger.Warn("failed to persist stats_file",
			zap.String("stats_file", i.StatsFile), zap.String("stage", stage), zap.Error(err))
	}
}

// setLogVars adds geojs_country and geojs_decision to the request context
// for access logging and debugging.
func setLogVars(r *http.Request, country, decision string) {
	caddyhttp.SetVar(r.Context(), "geojs_country", country)
	caddyhttp.SetVar(r.Context(), "geojs_decision", decision) // "allow" | "block" | "allow_ud" | "block_ud"
}

// Debug path

func (i *GeoJSBlocker) tryServeDebug(w http.ResponseWriter, r *http.Request) bool {
	path := strings.TrimSuffix(r.URL.Path, "/")
	if i.DebugPath == "" || path != i.DebugPath {
		return false
	}
	// token check (optional)
	if tok := strings.TrimSpace(i.DebugToken); tok != "" {
		if r.Header.Get("X-Debug-Token") != tok {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized"))
			return true
		}
	}
	// reset if requested
	if r.Method == http.MethodPost && (r.URL.Query().Get("reset") == "1" || r.URL.Query().Get("reset") == "true") {
		i.stats.reset()
		i.flushStatsFile("reset")
	}

	snap := i.stats.snapshot()
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(snap)
	return true
}

// Main handler

func (i *GeoJSBlocker) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Intercept debug endpoint early
	if i.tryServeDebug(w, r) {
		return nil
	}

	ipStr := clientIPFromRequest(r)
	if ipStr == "" {
		return i.onUndetected(w, r, next, "no_ip")
	}

	ip := net.ParseIP(ipStr)
	if ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
		i.logger.Debug("skip local/private IP (auto-allow)",
			zap.String("ip", ipStr))
		setLogVars(r, "LOCAL", "allow_local")
		return next.ServeHTTP(w, r)
	}

	// 1) cache
	if ctry, ok := i.cache.Get(ipStr); ok {
		i.stats.incCacheHit()
		return i.decide(ctry, w, r, next, true, ipStr)
	}

	// 2) lookup (with optional singleflight)
	fetch := func() (string, error) {
		i.stats.incApiCall()
		base := strings.TrimRight(i.apiBase, "/")
		apiURL := fmt.Sprintf("%s/%s", base, ipStr)
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, apiURL, nil)
		if err != nil {
			i.stats.incApiError()
			return "", err
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			i.stats.incApiError()
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			i.stats.incApiError()
			return "", fmt.Errorf("geojs bad status %d", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			i.stats.incApiError()
			return "", err
		}
		c := strings.ToUpper(strings.TrimSpace(string(body)))
		if len(c) != 2 {
			i.stats.incApiError()
			return "", fmt.Errorf("invalid country %q", c)
		}
		return c, nil
	}

	var (
		country string
		err     error
	)
	if i.useSF {
		v, errSF, _ := i.sfGroup.Do(ipStr, func() (interface{}, error) { return fetch() })
		if errSF != nil {
			i.logger.Warn("GeoJS lookup failed (singleflight)", zap.String("ip", ipStr), zap.Error(errSF))
			return i.onUndetected(w, r, next, "lookup_error")
		}
		country = v.(string)
	} else {
		country, err = fetch()
		if err != nil {
			i.logger.Warn("GeoJS lookup failed", zap.String("ip", ipStr), zap.Error(err))
			return i.onUndetected(w, r, next, "lookup_error")
		}
	}

	// store & decide
	i.cache.Set(ipStr, country)
	return i.decide(country, w, r, next, false, ipStr)
}

func (i *GeoJSBlocker) onUndetected(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, reason string) error {
	if i.allowUD {
		i.logger.Debug("country undetected -> allow", zap.String("reason", reason))
		setLogVars(r, "??", "allow_ud")
		i.stats.incAllow("??")
		return next.ServeHTTP(w, r)
	}
	i.logger.Warn("country undetected -> block", zap.String("reason", reason))
	setLogVars(r, "??", "block_ud")
	i.stats.incBlock("??")
	return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("country undetected"))
}

// decide applies allowlist or blocklist rules based on the configured
// mode and updates internal counters accordingly.
func (i *GeoJSBlocker) decide(country string, w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, fromCache bool, ip string) error {
	src := "lookup"
	if fromCache {
		src = "cache"
	}

	// Allowlist mode
	if len(i.Allowed) > 0 {
		if contains(i.Allowed, country) {
			setLogVars(r, country, "allow")
			i.logger.Debug("geojs allow (allowlist)",
				zap.String("ip", ip), zap.String("country", country), zap.String("source", src))
			if !fromCache {
				i.stats.incAllow(country)
			}
			return next.ServeHTTP(w, r)
		}
		setLogVars(r, country, "block")
		i.logger.Warn("geojs block (not in allowlist)",
			zap.String("ip", ip), zap.String("country", country), zap.String("source", src))
		if !fromCache {
			i.stats.incBlock(country)
		}
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("country not allowed"))
	}

	// Blocklist mode
	if len(i.Blocked) > 0 && contains(i.Blocked, country) {
		setLogVars(r, country, "block")
		i.logger.Warn("geojs block (blocklist)",
			zap.String("ip", ip), zap.String("country", country), zap.String("source", src))
		if !fromCache {
			i.stats.incBlock(country)
		}
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("country blocked"))
	}

	setLogVars(r, country, "allow")
	i.logger.Debug("geojs allow",
		zap.String("ip", ip), zap.String("country", country), zap.String("source", src))
	if !fromCache {
		i.stats.incAllow(country)
	}
	return next.ServeHTTP(w, r)
}

// Helpers

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// clientIPFromRequest extracts the client's IP address from common
// proxy headers (X-Forwarded-For, X-Real-IP) or the RemoteAddr field.
func clientIPFromRequest(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := net.ParseIP(strings.TrimSpace(parts[0])); ip != nil {
			return ip.String()
		}
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		if ip := net.ParseIP(strings.TrimSpace(xrip)); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
	}
	return ""
}

// Caddyfile parsing

func parseListAndOptions(h httpcaddyfile.Helper) (codes []string, ttl string, size int, sf string, allowUD string, dbgPath string, dbgTok string, pruneInt string, statsFile string, statsFlushInt string, err error) {
	d := h.Dispenser
	for d.Next() {
		// inline: treat as country codes
		codes = append(codes, d.RemainingArgs()...)
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			key := strings.ToLower(strings.TrimSpace(d.Val()))
			switch key {
			case "cache_ttl":
				args := d.RemainingArgs()
				if len(args) != 1 {
					return nil, "", 0, "", "", "", "", "", "", "", d.Errf("cache_ttl expects 1 argument (e.g., 15m)")
				}
				if _, perr := time.ParseDuration(args[0]); perr != nil {
					return nil, "", 0, "", "", "", "", "", "", "", d.Errf("invalid cache_ttl %q: %v", args[0], perr)
				}
				ttl = args[0]
			case "cache_size":
				args := d.RemainingArgs()
				if len(args) != 1 {
					return nil, "", 0, "", "", "", "", "", "", "", d.Errf("cache_size expects 1 integer argument")
				}
				n, perr := strconv.Atoi(args[0])
				if perr != nil || n <= 0 {
					return nil, "", 0, "", "", "", "", "", "", "", d.Errf("invalid cache_size %q", args[0])
				}
				size = n
			case "singleflight":
				args := d.RemainingArgs()
				if len(args) != 1 {
					return nil, "", 0, "", "", "", "", "", "", "", d.Errf("singleflight expects 'on' or 'off'")
				}
				sf = args[0]
			case "allow_undetected":
				args := d.RemainingArgs()
				if len(args) != 1 {
					return nil, "", 0, "", "", "", "", "", "", "", d.Errf("allow_undetected expects 'on' or 'off'")
				}
				allowUD = args[0]
			case "prune_interval":
				args := d.RemainingArgs()
				if len(args) != 1 {
					return nil, "", 0, "", "", "", "", "", "", "", d.Errf("prune_interval expects 1 duration (e.g., 5m)")
				}
				if _, perr := time.ParseDuration(args[0]); perr != nil {
					return nil, "", 0, "", "", "", "", "", "", "", d.Errf("invalid prune_interval %q: %v", args[0], perr)
				}
				pruneInt = args[0]
			case "debug_path":
				args := d.RemainingArgs()
				if len(args) != 1 {
					return nil, "", 0, "", "", "", "", "", "", "", d.Errf("debug_path expects 1 path (e.g., /debug/geojs)")
				}
				dbgPath = strings.TrimSpace(args[0])
			case "debug_token":
				args := d.RemainingArgs()
				if len(args) != 1 {
					return nil, "", 0, "", "", "", "", "", "", "", d.Errf("debug_token expects 1 value")
				}
				dbgTok = strings.TrimSpace(args[0])
			case "stats_file":
				args := d.RemainingArgs()
				if len(args) != 1 {
					return nil, "", 0, "", "", "", "", "", "", "", d.Errf("stats_file expects 1 path (e.g., /var/lib/caddy/geojs_stats.json)")
				}
				statsFile = strings.TrimSpace(args[0])
			case "stats_flush_interval":
				args := d.RemainingArgs()
				if len(args) != 1 {
					return nil, "", 0, "", "", "", "", "", "", "", d.Errf("stats_flush_interval expects 1 duration (e.g., 5m)")
				}
				if _, perr := time.ParseDuration(args[0]); perr != nil {
					return nil, "", 0, "", "", "", "", "", "", "", d.Errf("invalid stats_flush_interval %q: %v", args[0], perr)
				}
				statsFlushInt = args[0]
			default:
				// treat entire line as country codes: first token + remainder
				if key != "" {
					codes = append(codes, key)
				}
				codes = append(codes, d.RemainingArgs()...)
			}
		}
	}
	return codes, ttl, size, sf, allowUD, dbgPath, dbgTok, pruneInt, statsFile, statsFlushInt, nil
}

func parseCaddyfileDirectiveBlock(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var i GeoJSBlocker
	codes, ttl, size, sf, allowUD, dbgPath, dbgTok, pruneInt, statsFile, statsFlushInt, err := parseListAndOptions(h)
	if err != nil {
		return nil, err
	}
	i.Blocked = codes
	i.CacheTTL = ttl
	if size > 0 {
		i.CacheSize = size
	}
	if sf != "" {
		i.Singleflight = sf
	}
	if allowUD != "" {
		i.AllowUndetected = allowUD
	}
	i.PruneInterval = pruneInt
	i.DebugPath = dbgPath
	i.DebugToken = dbgTok
	i.StatsFile = statsFile
	i.StatsFlushInterval = statsFlushInt
	return &i, nil
}

func parseCaddyfileDirectiveAllow(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var i GeoJSBlocker
	codes, ttl, size, sf, allowUD, dbgPath, dbgTok, pruneInt, statsFile, statsFlushInt, err := parseListAndOptions(h)
	if err != nil {
		return nil, err
	}
	i.Allowed = codes
	i.CacheTTL = ttl
	if size > 0 {
		i.CacheSize = size
	}
	if sf != "" {
		i.Singleflight = sf
	}
	if allowUD != "" {
		i.AllowUndetected = allowUD
	}
	i.PruneInterval = pruneInt
	i.DebugPath = dbgPath
	i.DebugToken = dbgTok
	i.StatsFile = statsFile
	i.StatsFlushInterval = statsFlushInt
	return &i, nil
}

func init() {
	caddy.RegisterModule(GeoJSBlocker{})
	httpcaddyfile.RegisterHandlerDirective("geojs_block", parseCaddyfileDirectiveBlock)
	httpcaddyfile.RegisterHandlerDirective("geojs_allow", parseCaddyfileDirectiveAllow)
}
