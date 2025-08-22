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
	Long: `Authenticate with Google Calendar API using OAuth 2.0 device flow.

This command uses device flow authentication - no credentials needed!
Simply run the auth command and follow the on-screen instructions.

Examples:
  waybar-calendar-notify auth         # Start authentication
  waybar-calendar-notify auth --status # Check auth status
  waybar-calendar-notify auth --revoke # Clear authentication`,
	RunE: runAuth,
}

func init() {
	authCmd.Flags().BoolVar(&revokeFlag, "revoke", false, "clear local authentication")
	authCmd.Flags().BoolVar(&statusOnly, "status", false, "check authentication status only")
}

func runAuth(cmd *cobra.Command, args []string) error {
	// Initialize auth manager (no credentials needed)
	authManager, err := calendar.NewAuthManager(cacheDir, verbose)
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

	// Perform authentication via device flow
	fmt.Printf("%s Starting device authentication...\n", nerdfonts.InfoCircle)
	fmt.Println("Follow the instructions to complete Google Calendar authorization.")
	fmt.Println()

	// Create a calendar client to trigger auth flow
	_, err = calendar.NewClient(cacheDir, verbose, nil)
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
