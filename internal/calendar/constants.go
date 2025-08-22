package calendar

// OAuth 2.0 Constants for Google Calendar API
// These are public identifiers safe to embed in the source code

const (
	// Public OAuth 2.0 Client ID for Device Flow
	// This is safe to embed - it's a public identifier, not a secret
	// Device flow apps use a publicly distributed client ID
	GoogleOAuthClientID = "932772530018-fsdvskkmjbpkke2a3q2krmhbr9u2e6eh.apps.googleusercontent.com"

	// OAuth 2.0 endpoints
	DeviceAuthURL = "https://oauth2.googleapis.com/device/code"
	TokenURL      = "https://oauth2.googleapis.com/token"

	// Required scopes for calendar access
	ScopeCalendarReadonly = "https://www.googleapis.com/auth/calendar.readonly"
	ScopeCalendarEvents   = "https://www.googleapis.com/auth/calendar.events"
)

// CalendarScopes defines the OAuth scopes required for calendar access
var CalendarScopes = []string{
	ScopeCalendarReadonly,
	ScopeCalendarEvents,
}
