package cache

import (
	"strconv"
	"strings"
	"time"

	"github.com/bnema/waybar-calendar-notify/internal/calendar"
)

type CacheEntry struct {
	EventID    string    `json:"event_id"`
	Summary    string    `json:"summary"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`
	Location   string    `json:"location"`
	IsAllDay   bool      `json:"is_all_day"`
	Status     string    `json:"status"`
	IsBusy     bool      `json:"is_busy"`
	NotifiedAt []string  `json:"notified_at"` // ["15min", "5min", "start"]
	LastSeen   time.Time `json:"last_seen"`
}

func NewCacheEntry(event calendar.Event) CacheEntry {
	return CacheEntry{
		EventID:   event.ID,
		Summary:   event.Summary,
		StartTime: event.StartTime,
		EndTime:   event.EndTime,
		Location:  event.Location,
		IsAllDay:  event.IsAllDay,
		Status:    event.Status,
		IsBusy:    event.IsBusy,
		LastSeen:  time.Now(),
	}
}

func (ce *CacheEntry) ToEvent() calendar.Event {
	return calendar.Event{
		ID:        ce.EventID,
		Summary:   ce.Summary,
		StartTime: ce.StartTime,
		EndTime:   ce.EndTime,
		Location:  ce.Location,
		IsAllDay:  ce.IsAllDay,
		Status:    ce.Status,
		IsBusy:    ce.IsBusy,
	}
}

func (ce *CacheEntry) HasBeenNotifiedFor(notificationType string) bool {
	for _, notified := range ce.NotifiedAt {
		if notified == notificationType {
			return true
		}
	}
	return false
}

func (ce *CacheEntry) AddNotification(notificationType string) {
	if !ce.HasBeenNotifiedFor(notificationType) {
		ce.NotifiedAt = append(ce.NotifiedAt, notificationType)
	}
}

func (ce *CacheEntry) ShouldNotify(notificationType string, now time.Time) bool {
	// Don't notify if already notified for this type
	if ce.HasBeenNotifiedFor(notificationType) {
		return false
	}

	// Don't notify for cancelled events
	if ce.Status == "cancelled" {
		return false
	}

	// Don't notify for all-day events
	if ce.IsAllDay {
		return false
	}

	// Don't notify for transparent (not busy) events
	if !ce.IsBusy {
		return false
	}

	// Don't notify for events that already started
	if ce.StartTime.Before(now) && notificationType != "start" {
		return false
	}

	// Handle start notifications
	if notificationType == "start" {
		return ce.StartTime.Sub(now) <= 1*time.Minute && ce.StartTime.Sub(now) >= -1*time.Minute
	}

	// Handle minute-based notifications (e.g., "15min", "5min")
	if strings.HasSuffix(notificationType, "min") {
		minutesStr := strings.TrimSuffix(notificationType, "min")
		if minutes, err := strconv.Atoi(minutesStr); err == nil {
			timeUntil := ce.StartTime.Sub(now)
			windowStart := time.Duration(minutes) * time.Minute
			windowEnd := time.Duration(minutes-3) * time.Minute // 3-minute window
			if windowEnd < 0 {
				windowEnd = 0
			}
			return timeUntil <= windowStart && timeUntil > windowEnd
		}
	}

	return false
}

func (ce *CacheEntry) IsCurrentAt(t time.Time) bool {
	return t.After(ce.StartTime) && t.Before(ce.EndTime)
}

func (ce *CacheEntry) IsUpcomingAt(t time.Time) bool {
	return ce.StartTime.After(t)
}

func (ce *CacheEntry) IsExpired(maxAge time.Duration) bool {
	return time.Since(ce.LastSeen) > maxAge
}

func (ce *CacheEntry) UpdateFromEvent(event calendar.Event) {
	ce.Summary = event.Summary
	ce.StartTime = event.StartTime
	ce.EndTime = event.EndTime
	ce.Location = event.Location
	ce.IsAllDay = event.IsAllDay
	ce.Status = event.Status
	ce.IsBusy = event.IsBusy
	ce.LastSeen = time.Now()

	// Reset notifications if the event time changed significantly
	if ce.StartTime != event.StartTime {
		ce.NotifiedAt = []string{}
	}
}

func (ce *CacheEntry) GetTimeString() string {
	if ce.IsAllDay {
		return "All day"
	}

	start := ce.StartTime.Format("15:04")
	end := ce.EndTime.Format("15:04")

	// If it's on the same day, just show times
	if ce.StartTime.YearDay() == ce.EndTime.YearDay() {
		return start + "-" + end
	}

	// Multi-day event
	return ce.StartTime.Format("Jan 2 15:04") + "-" + ce.EndTime.Format("Jan 2 15:04")
}

func (ce *CacheEntry) GetShortSummary() string {
	if len(ce.Summary) <= 30 {
		return ce.Summary
	}
	return ce.Summary[:27] + "..."
}

func (ce *CacheEntry) MinutesUntilStart(t time.Time) int {
	if ce.StartTime.Before(t) {
		return 0
	}
	return int(ce.StartTime.Sub(t).Minutes())
}

func (ce *CacheEntry) Duration() time.Duration {
	return ce.EndTime.Sub(ce.StartTime)
}
