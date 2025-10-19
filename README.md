# Caddy GeoJS Blocker Module
![Go CI](https://github.com/tomsh-hr/caddy-geojs-blocker/actions/workflows/go.yml/badge.svg)

A lightweight **Caddy v2 HTTP handler module** for **geoblocking** or **geowhitelisting** requests based on client IP country codes, using the free [GeoJS API](https://www.geojs.io/).  
Supports both **allowlisting** (default allow, block others) and **blocklisting** (default allow, block specific).  
Includes per-instance caching, concurrency-safe stats, and an optional debug endpoint for monitoring.

---

## ✨ Features

- **GeoIP Lookup:** Fetches 2-letter country code (e.g., `DE`) from GeoJS.  
- **Caching:** In-memory LRU-like cache (default 50k entries, 15m TTL) to minimize API calls.  
- **Concurrency:** Optional `singleflight` deduplication for simultaneous lookups.  
- **Stats:** Atomic counters for allowed/blocked requests with JSON export.  
- **Log Vars:** Sets `geojs_country` and `geojs_decision` for access logs.  
- **Debug Endpoint:** Optional `/debug/geojs` endpoint for stats snapshot/reset (token-protected).

---

## ⚙️ Installation

### Build Caddy with the Module

Best way is to use **xcaddy**:

```bash
xcaddy build --with github.com/tomsh-hr/caddy-geojs-blocker
```

or:

```bash
# Clone Caddy
git clone https://github.com/caddyserver/caddy.git && cd caddy

# Add the module import
# In cmd/caddy/main.go:
import _ "github.com/tomsh-hr/caddy-geojs-blocker"

go mod tidy

# Build Caddy
go build \
  -tags 'nobadger,nomysql,nopgx' \
  -trimpath \
  -ldflags '-w -s' \
  -o ./caddy ./cmd/caddy
```

Then run:

```bash
./caddy run --config Caddyfile
```

---

## 🧩 Usage

Place the directive in a `route` block.

- Use **`geojs_allow`** for allowlisting (only specific countries allowed).  
- Use **`geojs_block`** for blocklisting (specific countries blocked).  

Inline arguments are ISO2 country codes; options are set within the block.

---

### ✅ Allow Only Specific Countries

```caddyfile
:80 {
  route {
    geojs_allow DE US RU CN {
      cache_ttl 30m
      debug_path /debug/geojs
    }
    respond "Hello from {http.vars.geojs_country}!"
  }
}
```

→ Allows Germany (`DE`), United States (`US`), Russia (`RU`), and China (`CN`); blocks all others with `403`.

---

### 🚫 Block Specific Countries

```caddyfile
:80 {
  route {
    geojs_block DE US RU CN
    respond "Access granted from {http.vars.geojs_country}!"
  }
}
```

→ Blocks Germany (`DE`), United States (`US`), Russia (`RU`), and China (`CN`); allows all others.

---

### 🧾 Full Example with All Options

```caddyfile
:80 {
  log {
    format json
  }

  route {
    geojs_allow DE US RU CN {
      cache_ttl 10m
      cache_size 10000
      singleflight off
      allow_undetected off
      prune_interval 2m
      debug_path /debug/geojs
      debug_token mysecret
    }

    respond "Welcome from {http.vars.geojs_country} ({http.vars.geojs_decision})"
  }
}
```

---

### Directive placement & order

`geojs_allow` and `geojs_block` are HTTP handlers. Use them inside a `route` block, or configure global ordering if you prefer global (site-wide) geoblocking.

**Preferred:**

```caddyfile
:80 {
  route {
    geojs_allow DE US RU CN
    respond "Hello from {http.vars.geojs_country}!"
  }
}
```

**Alternative with global order:**

```caddyfile
{
  order geojs_allow before respond
  order geojs_block before respond
}
:80 {
  geojs_allow DE US RU CN
  respond "Hello from {http.vars.geojs_country}!"
}
```

---

## 🔧 Options

| Option | Type | Description | Example | Default |
|--------|------|-------------|----------|----------|
| **Country Codes (inline)** | `[]string` | ISO2 codes for allow/block list | `geojs_allow DE US RU CN` | — |
| **cache_ttl** | Duration | Cache TTL for IP lookups | `cache_ttl 30m` | `15m` |
| **cache_size** | int | Max cache entries | `cache_size 10000` | `50000` |
| **singleflight** | string | Deduplicate concurrent lookups (`on/off`) | `singleflight off` | `on` |
| **allow_undetected** | string | Allow (`on`) or block (`off`) undetected IPs (lookup failures, etc.) | `allow_undetected off` | `on` |
| **prune_interval** | Duration | Prune expired cache entries | `prune_interval 1h` | `5m` |
| **debug_path** | string | Path for stats JSON endpoint | `debug_path /debug/geojs` | *(disabled)* |
| **debug_token** | string | Token for debug auth (header `X-Debug-Token`) | `debug_token mysecret` | *(none)* |

---

## ⚙️ Recommended Settings by Use Case

Different environments benefit from different cache and pruning settings.  
Here are suggested values you can tune to balance performance and accuracy.

| Scenario | Description | cache_ttl | cache_size | prune_interval | singleflight | Notes |
|-----------|--------------|------------|-------------|----------------|---------------|-------|
| 🏠 **Home Server / Personal Use** | Few visitors, low load | `30m` | `1000` | `10m` | `on` | Keeps memory use minimal and still avoids repeat lookups. |
| 🚀 **Low-Traffic Site** | Small business, blog, small API | `1h` | `10000` | `10m` | `on` | Reduces API requests while maintaining fresh lookups. |
| 🌍 **High-Traffic / Production** | Many visitors or global access | `6h` | `50000–100000` | `15m` | `on` | Minimizes API hits, faster response, more RAM usage. |
| 🧪 **Debug / Testing** | Development, frequent restarts | `5m` | `1000` | `1m` | `off` | More frequent lookups help see live GeoJS behavior. |

💡 **Tip:**  
For very high traffic, keep `singleflight on` — it prevents multiple concurrent lookups for the same IP and saves both time and API requests.

---

## 🐛 Debug Endpoint

If `debug_path` is set (e.g., `/debug/geojs`):

**GET** → Returns JSON stats:

```json
{
  "total_allowed": 4,
  "total_blocked": 0,
  "allowed_by_cc": { "DE": 2, "US": 1, "RU": 1, "CN": 0 },
  "blocked_by_cc": {}
}
```

**POST ?reset=1** → Resets counters.  
**Example:**
```bash
curl http://localhost:80/debug/geojs
curl -X POST http://localhost:80/debug/geojs?reset=1
```

Requires header `X-Debug-Token: {token}` if `debug_token` is set.  
**Example with token:**
```bash
curl -H "X-Debug-Token: mysecret" http://localhost:80/debug/geojs
curl -X POST -H "X-Debug-Token: mysecret" http://localhost:80/debug/geojs?reset=1
```

---

## ⚠️ Notes

- **API Usage:** GeoJS currently has *no fixed rate limits*, but may restrict users who make excessive requests. The in-memory cache and optional singleflight mode help reduce unnecessary lookups.  
- **IPv6 Support:** Fully supported.  
- **Proxy Headers:** Prefers `X-Forwarded-For`, then `X-Real-IP`, then `RemoteAddr`.  
- **Cache Eviction:** Uses simple random eviction when full (not full LRU).  
- **Validation:** You cannot mix both blocklist and allowlist in one directive.

---

## 🧪 Testing

```bash
# Test with known IP
curl -H "X-Forwarded-For: 91.64.46.1" http://localhost:80
# → DE IP → allowed

# View stats
curl http://localhost:80/debug/geojs

# View stats with token
curl -H "X-Debug-Token: mysecret" http://localhost:80/debug/geojs

# Reset counters (token protected)
curl -X POST -H "X-Debug-Token: mysecret" http://localhost:80/debug/geojs?reset=1
```

---

## 🪵 Logging Integration

If you want GeoJS Blocker’s decision data (`geojs_country`, `geojs_decision`) to appear in your main access logs, you can append them manually to log entries using the following Caddyfile block:

```caddyfile
log {
  format json
}

handle_errors {
  log_append geojs_country  {http.vars.geojs_country}
  log_append geojs_decision {http.vars.geojs_decision}
  respond "{http.error.status_code} {http.error.status_text}"
}

route {
  geojs_allow DE US RU CN
  
  log_append geojs_country  {http.vars.geojs_country}
  log_append geojs_decision {http.vars.geojs_decision}
}
```

This ensures both normal requests and blocked responses include the GeoJS decision context in your JSON access log output.

---

## 🌍 Supported Country Codes

GeoJS returns [ISO 3166-1 alpha-2](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2) country codes.  
You can use any of these two-letter codes (case-insensitive) in `geojs_allow` or `geojs_block` directives.  
The module automatically converts them to uppercase and ignores invalid entries.

---

## 📜 License

Licensed under the [MIT License](./LICENSE).

Contributions welcome!  
Built with ❤️ for [Caddy](https://caddyserver.com).
