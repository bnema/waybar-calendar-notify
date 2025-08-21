package main

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Middleware func(http.HandlerFunc) http.HandlerFunc

func withMiddleware(handler http.HandlerFunc, middlewares ...Middleware) http.HandlerFunc {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}

func requestLogger() Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			wrapped := &responseWriter{ResponseWriter: w, status: http.StatusOK}

			next(wrapped, r)

			slog.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapped.status,
				"duration_ms", time.Since(start).Milliseconds(),
				"ip", extractRealIP(r),
				"user_agent", r.Header.Get("User-Agent"),
				"referer", r.Header.Get("Referer"),
			)
		}
	}
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (w *responseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func securityHeaders() Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			headers := w.Header()
			
			// HSTS - Force HTTPS for 1 year, include subdomains
			headers.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
			
			// Content Security Policy - Strict policy
			csp := "default-src 'self'; " +
				"script-src 'self' 'unsafe-inline'; " +
				"style-src 'self' 'unsafe-inline'; " +
				"img-src 'self' data: https:; " +
				"connect-src 'self'; " +
				"font-src 'self'; " +
				"object-src 'none'; " +
				"base-uri 'self'; " +
				"frame-ancestors 'none'; " +
				"upgrade-insecure-requests"
			headers.Set("Content-Security-Policy", csp)
			
			// Additional security headers
			headers.Set("X-Frame-Options", "DENY")
			headers.Set("X-Content-Type-Options", "nosniff")
			headers.Set("X-XSS-Protection", "1; mode=block")
			headers.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			headers.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=()")
			
			// Remove server information
			headers.Set("Server", "")
			headers.Del("X-Powered-By")
			
			next(w, r)
		}
	}
}

func corsMiddleware() Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Strict CORS policy - only allow specific localhost origins
			allowedOrigins := []string{
				"http://localhost",
				"https://localhost",
				"http://127.0.0.1",
				"https://127.0.0.1",
			}

			isAllowed := origin == ""
			for _, allowed := range allowedOrigins {
				if strings.HasPrefix(origin, allowed) {
					isAllowed = true
					break
				}
			}

			if isAllowed && origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept")
				w.Header().Set("Access-Control-Max-Age", "300") // 5 minutes
				w.Header().Set("Access-Control-Allow-Credentials", "false")
			}

			// Handle preflight requests
			if r.Method == "OPTIONS" {
				if isAllowed {
					w.WriteHeader(http.StatusNoContent)
				} else {
					w.WriteHeader(http.StatusForbidden)
				}
				return
			}

			next(w, r)
		}
	}
}

func advancedRateLimiter(cfg *Config) Middleware {
	type bucket struct {
		tokens    int64
		lastCheck time.Time
		mu        sync.Mutex
	}

	buckets := make(map[string]*bucket)
	var bucketsLock sync.RWMutex

	// Cleanup routine to prevent memory leaks
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		
		for range ticker.C {
			bucketsLock.Lock()
			now := time.Now()
			for ip, b := range buckets {
				b.mu.Lock()
				if now.Sub(b.lastCheck) > cfg.RateLimitWindow*2 {
					delete(buckets, ip)
				}
				b.mu.Unlock()
			}
			bucketsLock.Unlock()
		}
	}()

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ip := extractRealIP(r)

			bucketsLock.RLock()
			b, exists := buckets[ip]
			bucketsLock.RUnlock()

			if !exists {
				bucketsLock.Lock()
				// Double-check after acquiring write lock
				if b, exists = buckets[ip]; !exists {
					b = &bucket{
						tokens:    int64(cfg.RateLimitBurst),
						lastCheck: time.Now(),
					}
					buckets[ip] = b
				}
				bucketsLock.Unlock()
			}

			b.mu.Lock()
			defer b.mu.Unlock()

			now := time.Now()
			elapsed := now.Sub(b.lastCheck)

			// Token bucket algorithm: add tokens based on elapsed time
			tokensToAdd := int64(elapsed.Seconds() * float64(cfg.RateLimitRequests) / cfg.RateLimitWindow.Seconds())
			b.tokens += tokensToAdd
			
			if b.tokens > int64(cfg.RateLimitBurst) {
				b.tokens = int64(cfg.RateLimitBurst)
			}
			b.lastCheck = now

			if b.tokens < 1 {
				retryAfter := int(cfg.RateLimitWindow.Seconds() / float64(cfg.RateLimitRequests))
				handleRateLimitError(w, r, ip, retryAfter)
				return
			}

			atomic.AddInt64(&b.tokens, -1)
			next(w, r)
		}
	}
}


// Extract real IP address considering proxy headers
func extractRealIP(r *http.Request) string {
	// Check X-Real-IP first (single proxy)
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		if parsed := net.ParseIP(strings.TrimSpace(ip)); parsed != nil {
			return parsed.String()
		}
	}

	// Check X-Forwarded-For (multiple proxies - take first non-private IP)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if parsed := net.ParseIP(ip); parsed != nil && !isPrivateIP(parsed) {
				return parsed.String()
			}
		}
		// If all IPs are private, use the first one
		if len(ips) > 0 {
			if parsed := net.ParseIP(strings.TrimSpace(ips[0])); parsed != nil {
				return parsed.String()
			}
		}
	}

	// Check Forwarded header (RFC 7239)
	if forwarded := r.Header.Get("Forwarded"); forwarded != "" {
		// Simple parsing for "for=IP" pattern
		parts := strings.Split(forwarded, ";")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "for=") {
				ip := strings.TrimPrefix(part, "for=")
				ip = strings.Trim(ip, "\"")
				if parsed := net.ParseIP(ip); parsed != nil {
					return parsed.String()
				}
			}
		}
	}

	// Fallback to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr might not have port
		return r.RemoteAddr
	}
	return ip
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Check for private IPv4 ranges
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
	}

	return false
}

func healthCheckMiddleware() Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Add health check specific headers
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Expires", "0")
			next(w, r)
		}
	}
}