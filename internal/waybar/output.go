package waybar

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bnema/waybar-calendar-notify/internal/cache"
	"github.com/bnema/waybar-calendar-notify/internal/nerdfonts"
)

type WaybarOutput struct {
	Text    string `json:"text"`
	Tooltip string `json:"tooltip"`
	Class   string `json:"class"`
}

type OutputFormatter struct {
	maxTooltipEvents int
	showLocation     bool
	showDescription  bool
	dateFormat       string
}

func NewOutputFormatter() *OutputFormatter {
	return &OutputFormatter{
		maxTooltipEvents: 10,
		showLocation:     true,
		showDescription:  true,
		dateFormat:       "15:04",
	}
}

func (of *OutputFormatter) SetMaxTooltipEvents(max int) {
	of.maxTooltipEvents = max
}

func (of *OutputFormatter) SetShowLocation(show bool) {
	of.showLocation = show
}

func (of *OutputFormatter) SetShowDescription(show bool) {
	of.showDescription = show
}

func (of *OutputFormatter) SetDateFormat(format string) {
	of.dateFormat = format
}

func (of *OutputFormatter) FormatCalendarOutput(allEvents []cache.CacheEntry, now time.Time) WaybarOutput {
	// Separate events by status
	currentEvents := of.filterCurrentEvents(allEvents, now)
	upcomingEvents := of.filterUpcomingTodayEvents(allEvents, now)
	
	text := of.generateStatusText(currentEvents, upcomingEvents, now)
	tooltip := of.generateTooltip(allEvents, now)
	class := of.determineClass(currentEvents, upcomingEvents, now)
	
	return WaybarOutput{
		Text:    text,
		Tooltip: tooltip,
		Class:   class,
	}
}

func (of *OutputFormatter) generateStatusText(currentEvents, upcomingEvents []cache.CacheEntry, now time.Time) string {
	// If there's a current event, show it
	if len(currentEvents) > 0 {
		event := currentEvents[0] // Show the first current event
		if len(currentEvents) > 1 {
			return fmt.Sprintf("%s %s (+%d)", nerdfonts.CircleDot, event.GetShortSummary(), len(currentEvents)-1)
		}
		return fmt.Sprintf("%s %s", nerdfonts.CircleDot, event.GetShortSummary())
	}

	// Show upcoming events count
	if len(upcomingEvents) > 0 {
		return fmt.Sprintf("%s %d", nerdfonts.Calendar, len(upcomingEvents))
	}

	// Check if we have events later today
	todaysEvents := of.filterTodaysEvents(upcomingEvents, now)
	if len(todaysEvents) > 0 {
		return fmt.Sprintf("%s %s", nerdfonts.CheckCircle, "Done") // All events done for today
	}

	// No events
	return nerdfonts.Calendar
}

func (of *OutputFormatter) generateTooltip(allEvents []cache.CacheEntry, now time.Time) string {
	var lines []string

	// Header with current date
	header := fmt.Sprintf("Today's Calendar (%s)", now.Format("Monday, Jan 2"))
	lines = append(lines, header)
	lines = append(lines, strings.Repeat("━", len(header)))
	lines = append(lines, "")

	// Get today's events
	todaysEvents := of.filterTodaysEvents(allEvents, now)
	
	if len(todaysEvents) == 0 {
		lines = append(lines, fmt.Sprintf("%s No events today", nerdfonts.Calendar))
		return strings.Join(lines, "\n")
	}

	// Sort events by start time
	events := of.sortEventsByStartTime(todaysEvents)
	
	// Limit the number of events shown
	maxEvents := of.maxTooltipEvents
	if len(events) > maxEvents {
		events = events[:maxEvents]
	}

	// Add each event
	for _, event := range events {
		eventLines := of.formatEventForTooltip(event, now)
		lines = append(lines, eventLines...)
		lines = append(lines, "")
	}

	// Add "more events" indicator if needed
	if len(todaysEvents) > maxEvents {
		remaining := len(todaysEvents) - maxEvents
		lines = append(lines, fmt.Sprintf("... and %d more events", remaining))
	}

	// Remove trailing empty line
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	return strings.Join(lines, "\n")
}

func (of *OutputFormatter) formatEventForTooltip(event cache.CacheEntry, now time.Time) []string {
	var lines []string
	
	// Determine event status symbol and time
	var symbol string
	var timeStr string
	
	if event.IsCurrentAt(now) {
		symbol = nerdfonts.CircleDot // Current event
		if event.IsAllDay {
			timeStr = "All day"
		} else {
			remaining := event.EndTime.Sub(now)
			timeStr = fmt.Sprintf("%s (%s left)", event.GetTimeString(), of.formatDuration(remaining))
		}
	} else if event.IsUpcomingAt(now) {
		symbol = nerdfonts.Clock // Upcoming event
		if event.IsAllDay {
			timeStr = "All day"
		} else {
			timeStr = event.GetTimeString()
		}
	} else {
		symbol = nerdfonts.CheckCircle // Past event
		timeStr = event.GetTimeString()
	}

	// Main event line
	eventLine := fmt.Sprintf("%s %s  %s", symbol, timeStr, event.Summary)
	lines = append(lines, eventLine)

	// Location (indented)
	if of.showLocation && event.Location != "" {
		locationLine := fmt.Sprintf("   %s %s", nerdfonts.MapPin, event.Location)
		lines = append(lines, locationLine)
	}

	return lines
}

func (of *OutputFormatter) determineClass(currentEvents, upcomingEvents []cache.CacheEntry, now time.Time) string {
	if len(currentEvents) > 0 {
		return "active"
	}
	
	if len(upcomingEvents) > 0 {
		// Check if any event is starting soon (within 15 minutes)
		for _, event := range upcomingEvents {
			if event.MinutesUntilStart(now) <= 15 {
				return "urgent"
			}
		}
		return "upcoming"
	}
	
	return "idle"
}

func (of *OutputFormatter) filterCurrentEvents(events []cache.CacheEntry, now time.Time) []cache.CacheEntry {
	var current []cache.CacheEntry
	for _, event := range events {
		if event.IsCurrentAt(now) && !event.IsAllDay {
			current = append(current, event)
		}
	}
	return current
}

func (of *OutputFormatter) filterUpcomingTodayEvents(events []cache.CacheEntry, now time.Time) []cache.CacheEntry {
	endOfDay := time.Date(now.Year(), now.Month(), now.Day(), 23, 59, 59, 0, now.Location())
	
	var upcoming []cache.CacheEntry
	for _, event := range events {
		if event.IsUpcomingAt(now) && event.StartTime.Before(endOfDay) {
			upcoming = append(upcoming, event)
		}
	}
	return upcoming
}

func (of *OutputFormatter) filterTodaysEvents(events []cache.CacheEntry, now time.Time) []cache.CacheEntry {
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	endOfDay := startOfDay.Add(24 * time.Hour).Add(-time.Nanosecond)

	var todaysEvents []cache.CacheEntry
	for _, event := range events {
		// Event overlaps with today
		if event.StartTime.Before(endOfDay) && event.EndTime.After(startOfDay) {
			todaysEvents = append(todaysEvents, event)
		}
	}
	return todaysEvents
}

func (of *OutputFormatter) sortEventsByStartTime(events []cache.CacheEntry) []cache.CacheEntry {
	// Simple bubble sort for small arrays
	sorted := make([]cache.CacheEntry, len(events))
	copy(sorted, events)
	
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i].StartTime.After(sorted[j].StartTime) {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	
	return sorted
}

func (of *OutputFormatter) formatDuration(duration time.Duration) string {
	if duration < 0 {
		return "0m"
	}
	
	if duration < time.Hour {
		minutes := int(duration.Minutes())
		return fmt.Sprintf("%dm", minutes)
	}

	hours := int(duration.Hours())
	minutes := int(duration.Minutes()) % 60
	
	if minutes == 0 {
		return fmt.Sprintf("%dh", hours)
	}
	
	return fmt.Sprintf("%dh%dm", hours, minutes)
}

// FormatJSONOutput outputs the WaybarOutput as JSON string
func FormatJSONOutput(output WaybarOutput) (string, error) {
	data, err := json.Marshal(output)
	if err != nil {
		return "", fmt.Errorf("failed to marshal waybar output: %w", err)
	}
	return string(data), nil
}

// FormatTextOutput outputs a simple text representation
func FormatTextOutput(output WaybarOutput) string {
	return output.Text
}