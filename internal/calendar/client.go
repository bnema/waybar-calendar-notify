package calendar

import (
	"fmt"
	"os"
	"path/filepath"
)

type Client struct {
	authManager *AuthManager
	service     *CalendarService
}

func NewClient(cacheDir string, opts *AuthOptions) (*Client, error) {
	if cacheDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		cacheDir = filepath.Join(homeDir, ".cache", "waybar-calendar-notify")
	}

	authManager, err := NewAuthManager(cacheDir, opts)
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
	}, nil
}

func (c *Client) GetTodaysEvents() ([]Event, error) {
	return c.service.GetTodaysEvents()
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