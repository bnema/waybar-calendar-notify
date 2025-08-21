package cmd

import (
	"fmt"
	"os"

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

This command uses device flow authentication for CLI applications and limited-input devices.
You'll need to provide your own client_secrets_device_oauth.json file.

Examples:
  waybar-calendar-notify auth                    # Authenticate with device flow
  waybar-calendar-notify auth --status           # Check authentication status
  waybar-calendar-notify auth --revoke           # Clear local authentication`,
	RunE: runAuth,
}

func init() {
	authCmd.Flags().BoolVar(&revokeFlag, "revoke", false, "clear local authentication")
	authCmd.Flags().BoolVar(&statusOnly, "status", false, "check authentication status only")
}

func runAuth(cmd *cobra.Command, args []string) error {
	// Configure client secrets path
	secretsPath := clientSecretsPath
	if secretsPath == "" {
		secretsPath = "client_secrets_device_oauth.json"
	}

	// Validate file exists
	if _, err := os.Stat(secretsPath); os.IsNotExist(err) {
		return fmt.Errorf("client secrets file not found: %s", secretsPath)
	}

	// Setup auth options
	opts := &calendar.AuthOptions{
		ClientSecretsPath: secretsPath,
	}

	// Initialize auth manager
	authManager, err := calendar.NewAuthManager(cacheDir, opts, verbose)
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
	_, err = calendar.NewClient(cacheDir, opts, verbose, nil)
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