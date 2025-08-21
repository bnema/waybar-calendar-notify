package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/bnema/waybar-calendar-notify/internal/cache"
	"github.com/bnema/waybar-calendar-notify/internal/calendar"
	"github.com/bnema/waybar-calendar-notify/internal/nerdfonts"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check the status of the calendar integration",
	Long: `Display the current status of the waybar-calendar-notify integration including:
- Authentication status
- Last sync time from cache
- Current cached events
- Today's upcoming events

This command helps you monitor whether the calendar integration is working correctly.`,
	RunE: runStatus,
}

func runStatus(cmd *cobra.Command, args []string) error {
	fmt.Println("=== Calendar Status ===")

	// Check authentication
	client, err := calendar.NewClient(cacheDir, nil, verbose, &cfg.Calendars)
	if err != nil {
		fmt.Printf("%s Authentication: Failed to initialize (%v)\n", nerdfonts.ExclamationTriangle, err)
	} else if client.HasValidToken() {
		fmt.Printf("%s Authentication: Valid\n", nerdfonts.CheckCircle)
	} else {
		fmt.Printf("%s Authentication: Required (run 'waybar-calendar-notify auth')\n", nerdfonts.ExclamationCircle)
	}

	fmt.Println("\n=== Cache Status ===")

	// Load and check cache
	eventCache := cache.New(cacheDir)
	if err := eventCache.Load(); err != nil {
		fmt.Printf("%s Failed to load cache: %v\n", nerdfonts.ExclamationTriangle, err)
		return nil
	}

	fmt.Printf("Cache directory: %s\n", eventCache.GetCacheDir())
	fmt.Printf("Cache file: %s\n", eventCache.GetFilePath())
	fmt.Printf("Cached events: %d\n", eventCache.EventCount())

	if !eventCache.LastSync.IsZero() {
		fmt.Printf("Last sync: %s (%s ago)\n", 
			eventCache.LastSync.Format("2006-01-02 15:04:05"),
			time.Since(eventCache.LastSync).Truncate(time.Second))
	} else {
		fmt.Println("Last sync: Never")
	}

	// Show today's events
	fmt.Println("\n=== Today's Events ===")
	todaysEvents := eventCache.GetTodaysEvents()
	
	if len(todaysEvents) == 0 {
		fmt.Printf("%s No events today\n", nerdfonts.Calendar)
		return nil
	}

	now := time.Now()
	current := 0
	upcoming := 0
	past := 0

	fmt.Printf("Total events today: %d\n\n", len(todaysEvents))

	// Categorize and display events
	for _, event := range todaysEvents {
		var status string
		var symbol string

		if event.IsCurrentAt(now) {
			symbol = nerdfonts.CircleDot
			status = "CURRENT"
			current++
		} else if event.IsUpcomingAt(now) {
			symbol = nerdfonts.Clock
			status = "UPCOMING"
			upcoming++
			
			minutes := event.MinutesUntilStart(now)
			if minutes < 60 {
				status = fmt.Sprintf("UPCOMING (in %dm)", minutes)
			} else if minutes < 1440 {
				status = fmt.Sprintf("UPCOMING (in %dh%dm)", minutes/60, minutes%60)
			}
		} else {
			symbol = nerdfonts.CheckCircle
			status = "COMPLETED"
			past++
		}

		fmt.Printf("%s %s %s - %s\n", symbol, event.GetTimeString(), event.Summary, status)
		
		if event.Location != "" {
			fmt.Printf("%s %s\n", nerdfonts.MapPin, event.Location)
		}

		// Show notification status
		if len(event.NotifiedAt) > 0 {
			fmt.Printf("     %s Notified: %v\n", nerdfonts.Bell, event.NotifiedAt)
		}
	}

	// Summary
	fmt.Printf("\nSummary: %d completed, %d current, %d upcoming\n", past, current, upcoming)

	// Check for events needing notifications
	events15min := eventCache.GetEventsNeedingNotification("15min", now)
	events5min := eventCache.GetEventsNeedingNotification("5min", now)
	eventsStart := eventCache.GetEventsNeedingNotification("start", now)

	if len(events15min) > 0 || len(events5min) > 0 || len(eventsStart) > 0 {
		fmt.Println("\n=== Pending Notifications ===")
		if len(events15min) > 0 {
			fmt.Printf("%s %d events need 15-minute notification\n", nerdfonts.Bell, len(events15min))
		}
		if len(events5min) > 0 {
			fmt.Printf("%s %d events need 5-minute notification\n", nerdfonts.Bell, len(events5min))
		}
		if len(eventsStart) > 0 {
			fmt.Printf("%s %d events need start notification\n", nerdfonts.Bell, len(eventsStart))
		}
	}

	return nil
}