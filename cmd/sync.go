package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/bnema/waybar-calendar-notify/internal/cache"
	"github.com/bnema/waybar-calendar-notify/internal/calendar"
	"github.com/bnema/waybar-calendar-notify/internal/config"
	"github.com/bnema/waybar-calendar-notify/internal/logger"
	"github.com/bnema/waybar-calendar-notify/internal/notifier"
	"github.com/bnema/waybar-calendar-notify/internal/waybar"
)

var (
	formatFlag       string
	notifyFlag       bool
	notifyUpcoming   bool
	cacheEvents      bool
	noTooltipFlag    bool
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync calendar events and output Waybar format",
	Long: `Sync calendar events from Google Calendar and output in Waybar JSON format.
	
This command fetches the latest events from your Google Calendar, caches them locally,
optionally sends notifications for upcoming events, and outputs the current status
in a format suitable for Waybar.

Examples:
  waybar-calendar-notify sync                    # Basic sync and output
  waybar-calendar-notify sync --format=text     # Output as plain text
  waybar-calendar-notify sync --notify-upcoming # Send notifications for upcoming events
  waybar-calendar-notify sync --no-tooltip      # Output JSON without tooltip`,
	RunE: runSync,
}

func init() {
	syncCmd.Flags().StringVar(&formatFlag, "format", "json", "output format (json/text)")
	syncCmd.Flags().BoolVar(&notifyFlag, "notify", false, "enable desktop notifications")
	syncCmd.Flags().BoolVar(&notifyUpcoming, "notify-upcoming", false, "send notifications for upcoming events")
	syncCmd.Flags().BoolVar(&cacheEvents, "cache-events", true, "cache events locally")
	syncCmd.Flags().BoolVar(&noTooltipFlag, "no-tooltip", false, "remove tooltip field from JSON output")
}

func runSync(cmd *cobra.Command, args []string) error {
	// Validate flags
	if noTooltipFlag && formatFlag != "json" {
		return fmt.Errorf("--no-tooltip flag can only be used with --format=json")
	}

	// Initialize cache
	eventCache := cache.New(cacheDir)
	if err := eventCache.Load(); err != nil {
		logger.Warn("failed to load cache", "error", err)
	}

	// Initialize calendar client
	client, err := calendar.NewClient(cacheDir, nil, verbose)
	if err != nil {
		return fmt.Errorf("failed to initialize calendar client: %w", err)
	}

	// Check authentication
	if !client.HasValidToken() {
		return fmt.Errorf("authentication required. Run 'waybar-calendar-notify auth' first")
	}

	// Fetch today's events
	events, err := client.GetTodaysEvents()
	if err != nil {
		// If we have cached events, use them and warn about API failure
		if !eventCache.HasEvents() {
			return fmt.Errorf("failed to fetch calendar events: %w", err)
		}
		logger.Warn("failed to fetch events, using cached data", "error", err)
	} else {
		// Update cache with new events
		if cacheEvents {
			newEvents := eventCache.UpdateEvents(events)
			if len(newEvents) > 0 {
				logger.Info("found new events", "count", len(newEvents))
			}

			if err := eventCache.Save(); err != nil {
				logger.Warn("failed to save cache", "error", err)
			}
		}
	}

	// Send notifications if requested or enabled in config
	notificationEnabled := notifyUpcoming || notifyFlag || cfg.Notifications.Enabled
	if notificationEnabled {
		if err := sendNotifications(eventCache, cfg); err != nil {
			logger.Warn("failed to send notifications", "error", err)
		}
	}

	// Generate output
	now := time.Now()
	formatter := waybar.NewOutputFormatter()
	formatter.SetMaxTooltipEvents(cfg.Display.MaxTooltipEvents)
	formatter.SetShowLocation(cfg.Display.ShowLocation)
	formatter.SetShowDescription(cfg.Display.ShowDescription)
	formatter.SetDateFormat(cfg.Display.DateFormat)
	
	cacheEntries := eventCache.GetTodaysEvents()
	
	output := formatter.FormatCalendarOutput(cacheEntries, now)

	// Handle no-tooltip flag
	if noTooltipFlag {
		output.Tooltip = ""
	}

	// Output result
	switch formatFlag {
	case "json":
		jsonOutput, err := waybar.FormatJSONOutput(output)
		if err != nil {
			return fmt.Errorf("failed to format JSON output: %w", err)
		}
		fmt.Println(jsonOutput)
	case "text":
		fmt.Println(waybar.FormatTextOutput(output))
	default:
		return fmt.Errorf("unknown format: %s (supported: json, text)", formatFlag)
	}

	return nil
}

func sendNotifications(eventCache *cache.Cache, cfg *config.Config) error {
	now := time.Now()
	n := notifier.New(true)

	// Use configured reminder times
	for _, minutes := range cfg.Notifications.ReminderTimes {
		notifyType := fmt.Sprintf("%dmin", minutes)
		events := eventCache.GetEventsNeedingNotification(notifyType, now)
		
		if len(events) > 0 {
			if err := n.SendBulkEventReminder(events, minutes); err != nil {
				return fmt.Errorf("failed to send %d-minute notifications: %w", minutes, err)
			}
			
			// Mark as notified
			for _, event := range events {
				eventCache.MarkAsNotified(event.EventID, notifyType)
			}
		}
	}

	// Check for events starting now
	eventsStart := eventCache.GetEventsNeedingNotification("start", now)
	if len(eventsStart) > 0 {
		if err := n.SendBulkEventReminder(eventsStart, 0); err != nil {
			return fmt.Errorf("failed to send start notifications: %w", err)
		}
		
		// Mark as notified
		for _, event := range eventsStart {
			eventCache.MarkAsNotified(event.EventID, "start")
		}
	}

	// Save cache with updated notification status
	return eventCache.Save()
}

