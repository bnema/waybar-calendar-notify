package calendar

import (
	"context"
	"fmt"
	"strings"
	"time"

	gcal "google.golang.org/api/calendar/v3"
	"google.golang.org/api/option"
	"github.com/bnema/waybar-calendar-notify/internal/logger"
)

type Event struct {
	ID          string
	CalendarID  string    // Calendar ID this event belongs to
	Summary     string
	Description string
	StartTime   time.Time
	EndTime     time.Time
	Location    string
	IsAllDay    bool
	Status      string // confirmed, tentative, cancelled
	Attendees   []Attendee
	IsBusy      bool // Based on transparency field
}

type Attendee struct {
	Email          string
	DisplayName    string
	ResponseStatus string // needsAction, declined, tentative, accepted
	Organizer      bool
	Self           bool
}

type CalendarService struct {
	service *gcal.Service
}

func NewCalendarService(authManager *AuthManager) (*CalendarService, error) {
	ctx := context.Background()
	client, err := authManager.GetClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get authenticated client: %w", err)
	}

	srv, err := gcal.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("failed to create calendar service: %w", err)
	}

	return &CalendarService{
		service: srv,
	}, nil
}

// ListCalendars retrieves all calendars accessible by the authenticated user
func (c *CalendarService) ListCalendars() ([]*gcal.CalendarListEntry, error) {
	ctx := context.Background()
	calendarList, err := c.service.CalendarList.List().Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve calendar list: %w", err)
	}
	return calendarList.Items, nil
}

func (c *CalendarService) GetTodaysEvents() ([]Event, error) {
	ctx := context.Background()

	// Get start and end of today
	now := time.Now()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	endOfDay := startOfDay.Add(24 * time.Hour).Add(-time.Nanosecond)

	return c.GetEventsInRange(ctx, startOfDay, endOfDay)
}

func (c *CalendarService) GetUpcomingEvents(hours int) ([]Event, error) {
	ctx := context.Background()
	now := time.Now()
	end := now.Add(time.Duration(hours) * time.Hour)

	return c.GetEventsInRange(ctx, now, end)
}

func (c *CalendarService) GetEventsInRange(ctx context.Context, timeMin, timeMax time.Time) ([]Event, error) {
	return c.GetEventsInRangeForCalendars(ctx, timeMin, timeMax, nil)
}

// GetEventsInRangeForCalendars retrieves events from specified calendars within a time range
func (c *CalendarService) GetEventsInRangeForCalendars(ctx context.Context, timeMin, timeMax time.Time, calendarIDs []string) ([]Event, error) {
	// If no calendar IDs specified, use primary only
	if len(calendarIDs) == 0 {
		calendarIDs = []string{"primary"}
	}
	
	var allEvents []Event
	for _, calID := range calendarIDs {
		logger.Debug("fetching events from calendar", "calendar_id", calID, "time_min", timeMin, "time_max", timeMax)
		
		events, err := c.service.Events.List(calID).
			TimeMin(timeMin.Format(time.RFC3339)).
			TimeMax(timeMax.Format(time.RFC3339)).
			SingleEvents(true).
			OrderBy("startTime").
			Context(ctx).
			Do()
		
		if err != nil {
			logger.Warn("failed to fetch events from calendar", "calendar_id", calID, "error", err)
			continue // Skip this calendar but continue with others
		}
		
		logger.Info("fetched events from calendar", "calendar_id", calID, "event_count", len(events.Items))
		
		for _, item := range events.Items {
			event, err := c.convertToEvent(item)
			if err != nil {
				logger.Debug("skipping invalid event", "event_id", item.Id, "error", err)
				continue
			}
			event.CalendarID = calID // Add calendar ID to event
			allEvents = append(allEvents, event)
		}
	}
	
	logger.Info("total events fetched", "total_count", len(allEvents), "calendar_count", len(calendarIDs))
	return allEvents, nil
}

func (c *CalendarService) GetCurrentEvents() ([]Event, error) {
	ctx := context.Background()
	now := time.Now()
	
	// Get events that started before now and end after now
	startTime := now.Add(-12 * time.Hour) // Look back 12 hours for current events
	endTime := now.Add(1 * time.Minute)   // Small buffer for events ending now

	events, err := c.GetEventsInRange(ctx, startTime, endTime)
	if err != nil {
		return nil, err
	}

	// Filter to only current events
	var currentEvents []Event
	for _, event := range events {
		if event.IsCurrentAt(now) {
			currentEvents = append(currentEvents, event)
		}
	}

	return currentEvents, nil
}

func (c *CalendarService) convertToEvent(item *gcal.Event) (Event, error) {
	event := Event{
		ID:          item.Id,
		Summary:     item.Summary,
		Description: item.Description,
		Location:    item.Location,
		Status:      item.Status,
		IsBusy:      item.Transparency != "transparent", // Default is busy unless explicitly transparent
	}

	// Parse start time
	var err error
	if item.Start.DateTime != "" {
		event.StartTime, err = time.Parse(time.RFC3339, item.Start.DateTime)
		if err != nil {
			return event, fmt.Errorf("failed to parse start time: %w", err)
		}
		event.IsAllDay = false
	} else if item.Start.Date != "" {
		event.StartTime, err = time.Parse("2006-01-02", item.Start.Date)
		if err != nil {
			return event, fmt.Errorf("failed to parse start date: %w", err)
		}
		event.IsAllDay = true
	} else {
		return event, fmt.Errorf("event has no start time or date")
	}

	// Parse end time
	if item.End.DateTime != "" {
		event.EndTime, err = time.Parse(time.RFC3339, item.End.DateTime)
		if err != nil {
			return event, fmt.Errorf("failed to parse end time: %w", err)
		}
	} else if item.End.Date != "" {
		event.EndTime, err = time.Parse("2006-01-02", item.End.Date)
		if err != nil {
			return event, fmt.Errorf("failed to parse end date: %w", err)
		}
	} else {
		// Default to 1 hour duration if no end time
		event.EndTime = event.StartTime.Add(time.Hour)
	}

	// Parse attendees
	for _, attendee := range item.Attendees {
		event.Attendees = append(event.Attendees, Attendee{
			Email:          attendee.Email,
			DisplayName:    attendee.DisplayName,
			ResponseStatus: attendee.ResponseStatus,
			Organizer:      attendee.Organizer,
			Self:           attendee.Self,
		})
	}

	return event, nil
}

// Helper methods for Event

func (e *Event) IsCurrentAt(t time.Time) bool {
	return t.After(e.StartTime) && t.Before(e.EndTime)
}

func (e *Event) IsUpcomingAt(t time.Time) bool {
	return e.StartTime.After(t)
}

func (e *Event) MinutesUntilStart(t time.Time) int {
	if e.StartTime.Before(t) {
		return 0
	}
	return int(e.StartTime.Sub(t).Minutes())
}

func (e *Event) MinutesUntilEnd(t time.Time) int {
	if e.EndTime.Before(t) {
		return 0
	}
	return int(e.EndTime.Sub(t).Minutes())
}

func (e *Event) Duration() time.Duration {
	return e.EndTime.Sub(e.StartTime)
}

func (e *Event) IsConfirmed() bool {
	return e.Status == "confirmed"
}

func (e *Event) IsTentative() bool {
	return e.Status == "tentative"
}

func (e *Event) IsCancelled() bool {
	return e.Status == "cancelled"
}

func (e *Event) ShouldNotify() bool {
	// Don't notify for all-day events, cancelled events, or transparent events
	return !e.IsAllDay && !e.IsCancelled() && e.IsBusy
}

func (e *Event) GetTimeString() string {
	if e.IsAllDay {
		return "All day"
	}

	start := e.StartTime.Format("15:04")
	end := e.EndTime.Format("15:04")
	
	// If it's on the same day, just show times
	if e.StartTime.YearDay() == e.EndTime.YearDay() {
		return fmt.Sprintf("%s-%s", start, end)
	}
	
	// Multi-day event
	return fmt.Sprintf("%s-%s", 
		e.StartTime.Format("Jan 2 15:04"), 
		e.EndTime.Format("Jan 2 15:04"))
}

func (e *Event) GetShortSummary() string {
	if len(e.Summary) <= 30 {
		return e.Summary
	}
	return e.Summary[:27] + "..."
}

func (e *Event) HasLocation() bool {
	return strings.TrimSpace(e.Location) != ""
}

func (e *Event) HasDescription() bool {
	return strings.TrimSpace(e.Description) != ""
}

func (e *Event) GetAttendeeCount() int {
	return len(e.Attendees)
}

func (e *Event) GetAcceptedAttendeeCount() int {
	count := 0
	for _, attendee := range e.Attendees {
		if attendee.ResponseStatus == "accepted" {
			count++
		}
	}
	return count
}