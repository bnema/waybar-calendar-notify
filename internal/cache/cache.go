package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/bnema/waybar-calendar-notify/internal/calendar"
)

type Cache struct {
	Events   []CacheEntry `json:"events"`
	LastSync time.Time    `json:"last_sync"`
	cacheDir string
	filePath string
}

func New(cacheDir string) *Cache {
	if cacheDir == "" {
		if defaultDir, err := GetDefaultCacheDir(); err == nil {
			cacheDir = defaultDir
		} else {
			cacheDir = "/tmp/waybar-calendar-notify"
		}
	}

	filePath := filepath.Join(cacheDir, "events.json")
	
	return &Cache{
		Events:   []CacheEntry{},
		LastSync: time.Time{},
		cacheDir: cacheDir,
		filePath: filePath,
	}
}

func (c *Cache) Load() error {
	// Ensure cache directory exists
	if err := os.MkdirAll(c.cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// If cache file doesn't exist, start with empty cache
	if _, err := os.Stat(c.filePath); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(c.filePath)
	if err != nil {
		return fmt.Errorf("failed to read cache file: %w", err)
	}

	if err := json.Unmarshal(data, c); err != nil {
		return fmt.Errorf("failed to unmarshal cache: %w", err)
	}

	return nil
}

func (c *Cache) Save() error {
	// Ensure cache directory exists
	if err := os.MkdirAll(c.cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cache: %w", err)
	}

	if err := os.WriteFile(c.filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	return nil
}

func (c *Cache) UpdateEvents(events []calendar.Event) []CacheEntry {
	c.LastSync = time.Now()
	
	// Create a map of existing events for quick lookup
	existingEvents := make(map[string]*CacheEntry)
	for i := range c.Events {
		existingEvents[c.Events[i].EventID] = &c.Events[i]
	}

	var newEvents []CacheEntry
	updatedEvents := make([]CacheEntry, 0, len(events))

	// Process each event from the API
	for _, event := range events {
		if existing, found := existingEvents[event.ID]; found {
			// Update existing event
			existing.UpdateFromEvent(event)
			updatedEvents = append(updatedEvents, *existing)
		} else {
			// New event
			newEntry := NewCacheEntry(event)
			updatedEvents = append(updatedEvents, newEntry)
			newEvents = append(newEvents, newEntry)
		}
	}

	// Keep only events that are not too old (within last 24 hours) or future events
	cutoff := time.Now().Add(-24 * time.Hour)
	var filteredEvents []CacheEntry
	for _, event := range updatedEvents {
		if event.EndTime.After(cutoff) {
			filteredEvents = append(filteredEvents, event)
		}
	}

	c.Events = filteredEvents
	return newEvents
}

func (c *Cache) GetEventsNeedingNotification(notificationType string, now time.Time) []CacheEntry {
	var needingNotification []CacheEntry
	
	for i := range c.Events {
		if c.Events[i].ShouldNotify(notificationType, now) {
			needingNotification = append(needingNotification, c.Events[i])
		}
	}
	
	return needingNotification
}

func (c *Cache) MarkAsNotified(eventID, notificationType string) {
	for i := range c.Events {
		if c.Events[i].EventID == eventID {
			c.Events[i].AddNotification(notificationType)
			break
		}
	}
}

func (c *Cache) GetCurrentEvents(now time.Time) []CacheEntry {
	var currentEvents []CacheEntry
	
	for _, event := range c.Events {
		if event.IsCurrentAt(now) {
			currentEvents = append(currentEvents, event)
		}
	}
	
	return currentEvents
}

func (c *Cache) GetUpcomingEvents(now time.Time) []CacheEntry {
	var upcomingEvents []CacheEntry
	
	for _, event := range c.Events {
		if event.IsUpcomingAt(now) {
			upcomingEvents = append(upcomingEvents, event)
		}
	}
	
	return upcomingEvents
}

func (c *Cache) GetTodaysEvents() []CacheEntry {
	now := time.Now()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	endOfDay := startOfDay.Add(24 * time.Hour).Add(-time.Nanosecond)

	var todaysEvents []CacheEntry
	
	for _, event := range c.Events {
		// Event overlaps with today
		if event.StartTime.Before(endOfDay) && event.EndTime.After(startOfDay) {
			todaysEvents = append(todaysEvents, event)
		}
	}
	
	return todaysEvents
}

func (c *Cache) GetEventByID(eventID string) *CacheEntry {
	for i := range c.Events {
		if c.Events[i].EventID == eventID {
			return &c.Events[i]
		}
	}
	return nil
}

func (c *Cache) HasEvents() bool {
	return len(c.Events) > 0
}

func (c *Cache) EventCount() int {
	return len(c.Events)
}

func (c *Cache) CleanOldEvents(maxAge time.Duration) int {
	cleaned := 0
	filtered := make([]CacheEntry, 0, len(c.Events))
	
	for _, event := range c.Events {
		if !event.IsExpired(maxAge) {
			filtered = append(filtered, event)
		} else {
			cleaned++
		}
	}
	
	c.Events = filtered
	return cleaned
}

func (c *Cache) GetFilePath() string {
	return c.filePath
}

func (c *Cache) GetCacheDir() string {
	return c.cacheDir
}

func GetDefaultCacheDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(homeDir, ".cache", "waybar-calendar-notify"), nil
}