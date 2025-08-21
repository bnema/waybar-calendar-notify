package calendar

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
	gcal "google.golang.org/api/calendar/v3"
	"github.com/bnema/waybar-calendar-notify/internal/config"
	"github.com/bnema/waybar-calendar-notify/internal/logger"
)

type Client struct {
	authManager *AuthManager
	service     *CalendarService
	config      *config.CalendarConfig  // Calendar configuration
}

func NewClient(cacheDir string, opts *AuthOptions, verbose bool, cfg *config.CalendarConfig) (*Client, error) {
	if cacheDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		cacheDir = filepath.Join(homeDir, ".cache", "waybar-calendar-notify")
	}

	authManager, err := NewAuthManager(cacheDir, opts, verbose)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth manager: %w", err)
	}

	service, err := NewCalendarService(authManager)
	if err != nil {
		return nil, fmt.Errorf("failed to create calendar service: %w", err)
	}

	return &Client{
		authManager: authManager,
		service:     service,
		config:      cfg,
	}, nil
}

func (c *Client) GetTodaysEvents() ([]Event, error) {
	ctx := context.Background()
	now := time.Now()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	endOfDay := startOfDay.Add(24 * time.Hour).Add(-time.Nanosecond)
	
	// Determine which calendars to fetch from
	var calendarIDs []string
	if c.config != nil && !c.config.PrimaryOnly {
		if len(c.config.CalendarIDs) > 0 {
			calendarIDs = c.config.CalendarIDs
		} else {
			// Auto-discover all calendars
			calendars, err := c.service.ListCalendars()
			if err != nil {
				logger.Warn("failed to list calendars, falling back to primary", "error", err)
				calendarIDs = []string{"primary"}
			} else {
				for _, cal := range calendars {
					calendarIDs = append(calendarIDs, cal.Id)
					logger.Debug("discovered calendar", "id", cal.Id, "summary", cal.Summary)
				}
			}
		}
	} else {
		calendarIDs = []string{"primary"}
	}
	
	logger.Info("fetching today's events", "calendar_count", len(calendarIDs))
	return c.service.GetEventsInRangeForCalendars(ctx, startOfDay, endOfDay, calendarIDs)
}

// GetCalendarList retrieves the list of all accessible calendars
func (c *Client) GetCalendarList() ([]*gcal.CalendarListEntry, error) {
	return c.service.ListCalendars()
}

func (c *Client) GetUpcomingEvents(hours int) ([]Event, error) {
	return c.service.GetUpcomingEvents(hours)
}

func (c *Client) GetCurrentEvents() ([]Event, error) {
	return c.service.GetCurrentEvents()
}

func (c *Client) HasValidToken() bool {
	return c.authManager.HasValidToken()
}

func (c *Client) GetAuthManager() *AuthManager {
	return c.authManager
}

// GetDefaultCacheDir returns the default cache directory path
func GetDefaultCacheDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(homeDir, ".cache", "waybar-calendar-notify"), nil
}