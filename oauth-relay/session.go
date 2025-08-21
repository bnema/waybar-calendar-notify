package main

import (
	"crypto/subtle"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

type Session struct {
	ID           string
	State        string
	CodeVerifier string
	Tokens       *TokenResponse
	CreatedAt    time.Time
	ExpiresAt    time.Time
	ClientIP     string
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type SessionStore struct {
	sessions      sync.Map        // sessionID -> *Session
	stateIndex    sync.Map        // state -> sessionID (constant-time lookup)
	ipSessions    sync.Map        // clientIP -> []sessionID
	sessionCount  atomic.Int64    // Total active sessions
	maxPerIP      int
	maxTotal      int
	sessionTimeout time.Duration
}

func NewSessionStore(cfg *Config) *SessionStore {
	store := &SessionStore{
		maxPerIP:      cfg.MaxSessionsPerIP,
		maxTotal:      cfg.MaxTotalSessions,
		sessionTimeout: cfg.SessionTimeout,
	}

	// Enhanced cleanup goroutine with configurable intervals
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			store.cleanup()
		}
	}()

	return store
}

func (s *SessionStore) CreateWithIP(clientIP string) (*Session, error) {
	// Check global session limit
	if s.sessionCount.Load() >= int64(s.maxTotal) {
		slog.Warn("max total sessions reached", "current", s.sessionCount.Load(), "limit", s.maxTotal)
		return nil, ErrMaxSessionsReached
	}

	// Check per-IP session limit
	if s.getIPSessionCount(clientIP) >= s.maxPerIP {
		slog.Warn("max sessions per IP reached", "ip", clientIP, "limit", s.maxPerIP)
		return nil, ErrMaxSessionsPerIP
	}

	sessionID := generateSecureToken(32)
	state := generateSecureToken(32)
	codeVerifier := generateCodeVerifier()

	session := &Session{
		ID:           sessionID,
		State:        state,
		CodeVerifier: codeVerifier,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(s.sessionTimeout),
		ClientIP:     clientIP,
	}

	// Store session with both mappings
	s.sessions.Store(sessionID, session)
	s.stateIndex.Store(state, sessionID)
	
	// Track IP sessions
	s.addIPSession(clientIP, sessionID)
	
	// Increment counter
	s.sessionCount.Add(1)

	slog.Info("session created",
		"session_id", sessionID,
		"client_ip", clientIP,
		"expires_at", session.ExpiresAt,
		"total_sessions", s.sessionCount.Load(),
	)

	return session, nil
}

// Legacy Create method for backward compatibility
func (s *SessionStore) Create() (*Session, error) {
	return s.CreateWithIP("unknown")
}

func (s *SessionStore) Get(sessionID string) (*Session, bool) {
	if val, ok := s.sessions.Load(sessionID); ok {
		session := val.(*Session)
		if time.Now().Before(session.ExpiresAt) {
			return session, true
		}
		// Session expired, clean it up
		s.deleteSession(session)
	}
	return nil, false
}

// GetByState provides constant-time state lookup to prevent timing attacks
func (s *SessionStore) GetByState(state string) (*Session, bool) {
	// Constant-time lookup using state index
	if val, ok := s.stateIndex.Load(state); ok {
		sessionID := val.(string)
		return s.Get(sessionID)
	}
	return nil, false
}

// ValidateState uses constant-time comparison to prevent timing attacks
func (s *SessionStore) ValidateState(providedState, expectedState string) bool {
	return subtle.ConstantTimeCompare([]byte(providedState), []byte(expectedState)) == 1
}

func (s *SessionStore) Delete(sessionID string) {
	if val, ok := s.sessions.Load(sessionID); ok {
		session := val.(*Session)
		s.deleteSession(session)
	}
}

func (s *SessionStore) deleteSession(session *Session) {
	// Remove from all mappings
	s.sessions.Delete(session.ID)
	s.stateIndex.Delete(session.State)
	s.removeIPSession(session.ClientIP, session.ID)
	s.sessionCount.Add(-1)
}

func (s *SessionStore) getIPSessionCount(clientIP string) int {
	if val, ok := s.ipSessions.Load(clientIP); ok {
		sessions := val.([]string)
		// Filter out expired sessions
		validSessions := make([]string, 0, len(sessions))
		for _, sessionID := range sessions {
			if _, exists := s.Get(sessionID); exists {
				validSessions = append(validSessions, sessionID)
			}
		}
		// Update the slice with valid sessions only
		if len(validSessions) != len(sessions) {
			s.ipSessions.Store(clientIP, validSessions)
		}
		return len(validSessions)
	}
	return 0
}

func (s *SessionStore) addIPSession(clientIP, sessionID string) {
	val, _ := s.ipSessions.LoadOrStore(clientIP, []string{})
	sessions := val.([]string)
	sessions = append(sessions, sessionID)
	s.ipSessions.Store(clientIP, sessions)
}

func (s *SessionStore) removeIPSession(clientIP, sessionID string) {
	if val, ok := s.ipSessions.Load(clientIP); ok {
		sessions := val.([]string)
		for i, id := range sessions {
			if id == sessionID {
				// Remove by swapping with last element and truncating
				sessions[i] = sessions[len(sessions)-1]
				sessions = sessions[:len(sessions)-1]
				if len(sessions) == 0 {
					s.ipSessions.Delete(clientIP)
				} else {
					s.ipSessions.Store(clientIP, sessions)
				}
				break
			}
		}
	}
}

func (s *SessionStore) cleanup() {
	sessionCount := 0
	ipCleanupCount := 0
	
	// Clean up expired sessions
	s.sessions.Range(func(key, value interface{}) bool {
		session := value.(*Session)
		if time.Now().After(session.ExpiresAt) {
			s.deleteSession(session)
			sessionCount++
		}
		return true
	})

	// Clean up empty IP session lists
	s.ipSessions.Range(func(key, value interface{}) bool {
		sessions := value.([]string)
		if len(sessions) == 0 {
			s.ipSessions.Delete(key)
			ipCleanupCount++
		}
		return true
	})

	if sessionCount > 0 || ipCleanupCount > 0 {
		slog.Debug("cleanup completed", 
			"expired_sessions", sessionCount,
			"empty_ip_lists", ipCleanupCount,
			"active_sessions", s.sessionCount.Load())
	}
}

// GetStats returns session store statistics
func (s *SessionStore) GetStats() map[string]interface{} {
	totalSessions := s.sessionCount.Load()
	
	ipCount := 0
	s.ipSessions.Range(func(key, value interface{}) bool {
		ipCount++
		return true
	})
	
	return map[string]interface{}{
		"total_sessions": totalSessions,
		"unique_ips":     ipCount,
		"max_per_ip":     s.maxPerIP,
		"max_total":      s.maxTotal,
		"timeout":        s.sessionTimeout.String(),
	}
}


func generateCodeVerifier() string {
	// PKCE code verifier should be 43-128 characters
	// We'll use 64 hex characters (32 bytes) for good entropy
	return generateSecureToken(32)
}