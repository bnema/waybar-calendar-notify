package cmd

import (
	"fmt"

	"github.com/bnema/waybar-calendar-notify/internal/calendar"
	"github.com/bnema/waybar-calendar-notify/internal/nerdfonts"
	"github.com/spf13/cobra"
)

var calendarsCmd = &cobra.Command{
	Use:   "calendars",
	Short: "List available calendars",
	Long: `List all calendars accessible with your Google account.

This command shows all calendars you have access to, including their IDs which you can
use in the configuration file to specify which calendars to sync events from.

Example:
  waybar-calendar-notify calendars`,
	RunE: runCalendars,
}

func runCalendars(cmd *cobra.Command, args []string) error {
	client, err := calendar.NewClient(cacheDir, verbose, nil)
	if err != nil {
		return fmt.Errorf("failed to initialize calendar client: %w", err)
	}

	if !client.HasValidToken() {
		return fmt.Errorf("authentication required. Run 'waybar-calendar-notify auth' first")
	}

	calendars, err := client.GetCalendarList()
	if err != nil {
		return fmt.Errorf("failed to list calendars: %w", err)
	}

	fmt.Println("=== Available Calendars ===")
	for _, cal := range calendars {
		icon := nerdfonts.Calendar
		if cal.Primary {
			icon = nerdfonts.CheckCircle + " " + nerdfonts.Calendar
		}

		fmt.Printf("%s %s\n", icon, cal.Summary)
		fmt.Printf("  ID: %s\n", cal.Id)
		if cal.Description != "" {
			fmt.Printf("  Description: %s\n", cal.Description)
		}
		fmt.Printf("  Access Role: %s\n", cal.AccessRole)
		if cal.Primary {
			fmt.Printf("  Primary: Yes\n")
		}
		fmt.Println()
	}

	fmt.Printf("Total calendars: %d\n", len(calendars))
	fmt.Println("\nTo use specific calendars, add their IDs to your config file:")
	fmt.Println("~/.config/waybar-calendar-notify/config.toml")

	return nil
}

func init() {
	rootCmd.AddCommand(calendarsCmd)
}
