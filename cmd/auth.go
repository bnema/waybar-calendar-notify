package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/bnema/waybar-calendar-notify/internal/calendar"
	"github.com/bnema/waybar-calendar-notify/internal/nerdfonts"
)

var (
	revokeFlag bool
	statusOnly bool
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage Google Calendar authentication",
	Long: `Authenticate with Google Calendar API using the OAuth relay service.

This command provides seamless authentication without requiring any setup or
credential management. Authentication is handled through our secure relay service.

Examples:
  waybar-calendar-notify auth                    # Authenticate with Google Calendar
  waybar-calendar-notify auth --status           # Check authentication status
  waybar-calendar-notify auth --revoke           # Clear local authentication`,
	RunE: runAuth,
}

func init() {
	authCmd.Flags().BoolVar(&revokeFlag, "revoke", false, "clear local authentication")
	authCmd.Flags().BoolVar(&statusOnly, "status", false, "check authentication status only")
}

func runAuth(cmd *cobra.Command, args []string) error {
	// Setup auth options for relay service (uses build-time injected URL)
	opts := &calendar.AuthOptions{
		UseRelay: true,
		// RelayURL will use the build-time injected value by default
	}

	// Initialize auth manager
	authManager, err := calendar.NewAuthManager(cacheDir, opts)
	if err != nil {
		return fmt.Errorf("failed to initialize auth manager: %w", err)
	}

	// Handle status check only
	if statusOnly {
		if authManager.HasValidToken() {
			fmt.Printf("%s Authentication: Valid\n", nerdfonts.CheckCircle)
		} else {
			fmt.Printf("%s Authentication: Required\n", nerdfonts.ExclamationCircle)
		}
		return nil
	}

	// Handle revoke (clear local token)
	if revokeFlag {
		fmt.Printf("%s Clearing authentication...\n", nerdfonts.InfoCircle)
		if err := authManager.ClearLocalToken(); err != nil {
			return fmt.Errorf("failed to clear authentication: %w", err)
		}
		fmt.Printf("%s Authentication cleared successfully\n", nerdfonts.CheckCircle)
		return nil
	}

	// Check current authentication status
	if authManager.HasValidToken() {
		fmt.Printf("%s Already authenticated with Google Calendar\n", nerdfonts.CheckCircle)
		fmt.Println("Use --revoke to re-authenticate or --status to check status")
		return nil
	}

	// Perform authentication via relay service
	fmt.Printf("%s Starting authentication...\n", nerdfonts.InfoCircle)
	fmt.Println("This will open your browser to complete Google Calendar authorization.")
	fmt.Println()

	// Create a calendar client to trigger auth flow
	_, err = calendar.NewClient(cacheDir, opts)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Verify authentication worked
	if !authManager.HasValidToken() {
		return fmt.Errorf("authentication completed but token is not valid")
	}

	fmt.Printf("%s Authentication successful!\n", nerdfonts.CheckCircle)
	fmt.Println("You can now use 'waybar-calendar-notify sync' to fetch your calendar events.")

	return nil
}