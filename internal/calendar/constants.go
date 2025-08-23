package calendar

// OAuth 2.0 identifiers & endpoints for Google Calendar API.
// Client ID & Secret are variables (not const) so they can be replaced at build time via:
//   go build -ldflags "-X github.com/bnema/waybar-calendar-notify/internal/calendar.GoogleOAuthClientID=YOUR_ID -X github.com/bnema/waybar-calendar-notify/internal/calendar.GoogleOAuthClientSecret=YOUR_SECRET"
// They can also be overridden at runtime via environment variables handled in device_auth.go.
// NOTE: Shipping a real client secret in an open-source binary offers no secrecy; prefer user-provided credentials.

var (
	// Default public OAuth 2.0 Client ID (safe to publish)
	GoogleOAuthClientID = ""
	// Left empty by default; supply if Google project requires a secret for device flow.
	GoogleOAuthClientSecret = ""
)

// Static constants
const (
	DeviceAuthURL = "https://oauth2.googleapis.com/device/code"
	TokenURL      = "https://oauth2.googleapis.com/token"

	ScopeCalendarReadonly = "https://www.googleapis.com/auth/calendar.readonly"
	ScopeCalendarEvents   = "https://www.googleapis.com/auth/calendar.events"
)

// CalendarScopes defines the OAuth scopes required for calendar access
var CalendarScopes = []string{ScopeCalendarReadonly}
