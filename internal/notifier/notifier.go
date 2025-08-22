package notifier

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/bnema/waybar-calendar-notify/internal/cache"
	"github.com/bnema/waybar-calendar-notify/internal/nerdfonts"
)

type Notifier struct {
	enabled bool
}

func New(enabled bool) *Notifier {
	return &Notifier{
		enabled: enabled,
	}
}

func (n *Notifier) SendEventReminder(event cache.CacheEntry, minutesBefore int) error {
	if !n.enabled {
		return nil
	}

	var title string
	switch minutesBefore {
	case 15:
		title = fmt.Sprintf("%s %s in 15 minutes", nerdfonts.CalendarClock, event.GetShortSummary())
	case 5:
		title = fmt.Sprintf("%s %s in 5 minutes", nerdfonts.CalendarClock, event.GetShortSummary())
	case 0:
		title = fmt.Sprintf("%s %s starting now", nerdfonts.CalendarDay, event.GetShortSummary())
	default:
		title = fmt.Sprintf("%s %s in %d minutes", nerdfonts.CalendarClock, event.GetShortSummary(), minutesBefore)
	}

	message := n.formatEventMessage(event)
	urgency := n.getUrgency(minutesBefore)

	return n.sendNotifyNotification(title, message, urgency)
}

func (n *Notifier) SendBulkEventReminder(events []cache.CacheEntry, minutesBefore int) error {
	if !n.enabled || len(events) == 0 {
		return nil
	}

	if len(events) == 1 {
		return n.SendEventReminder(events[0], minutesBefore)
	}

	var title string
	switch minutesBefore {
	case 15:
		title = fmt.Sprintf("%s %d events in 15 minutes", nerdfonts.CalendarClock, len(events))
	case 5:
		title = fmt.Sprintf("%s %d events in 5 minutes", nerdfonts.CalendarClock, len(events))
	case 0:
		title = fmt.Sprintf("%s %d events starting now", nerdfonts.CalendarDay, len(events))
	default:
		title = fmt.Sprintf("%s %d events in %d minutes", nerdfonts.CalendarClock, len(events), minutesBefore)
	}

	message := n.formatBulkEventMessage(events)
	urgency := n.getUrgency(minutesBefore)

	return n.sendNotifyNotification(title, message, urgency)
}

func (n *Notifier) formatEventMessage(event cache.CacheEntry) string {
	var parts []string

	// Time information
	if !event.IsAllDay {
		timeStr := fmt.Sprintf("%s %s", nerdfonts.Clock, event.GetTimeString())
		parts = append(parts, timeStr)
	}

	// Location information
	if event.Location != "" {
		locationStr := fmt.Sprintf("%s %s", nerdfonts.MapPin, event.Location)
		parts = append(parts, locationStr)
	}

	// Duration information for longer events
	duration := event.Duration()
	if duration >= 2*time.Hour && !event.IsAllDay {
		durationStr := fmt.Sprintf("%s %s", nerdfonts.Hourglass, n.formatDuration(duration))
		parts = append(parts, durationStr)
	}

	return strings.Join(parts, "\n")
}

func (n *Notifier) formatBulkEventMessage(events []cache.CacheEntry) string {
	var lines []string

	// Show up to 5 events
	count := len(events)
	if count > 5 {
		count = 5
	}

	for i := 0; i < count; i++ {
		event := events[i]
		var eventLine string

		if event.IsAllDay {
			eventLine = fmt.Sprintf("%s %s", nerdfonts.CalendarDay, event.GetShortSummary())
		} else {
			eventLine = fmt.Sprintf("%s %s %s", nerdfonts.Clock, event.StartTime.Format("15:04"), event.GetShortSummary())
		}

		if event.Location != "" {
			eventLine += fmt.Sprintf(" (%s %s)", nerdfonts.MapPin, event.Location)
		}

		lines = append(lines, eventLine)
	}

	if len(events) > 5 {
		lines = append(lines, fmt.Sprintf("... and %d more events", len(events)-5))
	}

	return strings.Join(lines, "\n")
}

func (n *Notifier) formatDuration(duration time.Duration) string {
	if duration < time.Hour {
		return fmt.Sprintf("%.0fm", duration.Minutes())
	}

	hours := duration.Hours()
	if hours < 24 {
		if hours == float64(int(hours)) {
			return fmt.Sprintf("%.0fh", hours)
		}
		return fmt.Sprintf("%.1fh", hours)
	}

	days := hours / 24
	return fmt.Sprintf("%.1fd", days)
}

func (n *Notifier) getUrgency(minutesBefore int) string {
	switch {
	case minutesBefore <= 0:
		return "critical"
	case minutesBefore <= 5:
		return "normal"
	default:
		return "low"
	}
}

func (n *Notifier) sendNotifyNotification(title, message, urgency string) error {
	args := []string{
		"--app-name=Calendar Notify",
		"--urgency=" + urgency,
		"--action", "default=Open Google Calendar",
		"--wait",
		title,
		message,
	}

	cmd := exec.Command("notify-send", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("notify-send failed: %w, output: %s", err, string(output))
	}

	// Handle the action response (this runs in background)
	go n.handleNotificationAction(strings.TrimSpace(string(output)))

	return nil
}

func (n *Notifier) handleNotificationAction(response string) {
	if response == "default" {
		// Open Google Calendar in default browser
		cmd := exec.Command("xdg-open", "https://calendar.google.com")
		if err := cmd.Run(); err != nil {
			// Log error but don't fail - browser opening is not critical
			fmt.Printf("Warning: failed to open browser: %v\n", err)
		}
	}
}

func (n *Notifier) IsEnabled() bool {
	return n.enabled
}

func (n *Notifier) SetEnabled(enabled bool) {
	n.enabled = enabled
}

func (n *Notifier) TestNotification() error {
	if !n.enabled {
		return fmt.Errorf("notifications are disabled")
	}

	title := fmt.Sprintf("%s Test Notification", nerdfonts.Calendar)
	message := fmt.Sprintf("%s This is a test notification from waybar-calendar-notify", nerdfonts.InfoCircle)

	return n.sendNotifyNotification(title, message, "low")
}
