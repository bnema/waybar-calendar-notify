package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/bnema/waybar-calendar-notify/internal/calendar"
	"github.com/bnema/waybar-calendar-notify/internal/nerdfonts"
)

var (
	revokeFlag     bool
	statusOnly     bool
	useDeviceFlow  bool
	useLocalServer bool
	customCredFile string
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage Google Calendar authentication",
	Long: `Authenticate with Google Calendar API using various methods.

SIMPLIFIED USAGE (Recommended):
  waybar-calendar-notify auth                    # Auto-select best method (device flow by default)
  
ADVANCED USAGE:
  waybar-calendar-notify auth --device-flow      # Force device flow (works everywhere)
  waybar-calendar-notify auth --local-server     # Force local server flow (requires browser)
  waybar-calendar-notify auth --custom-creds ./credentials.json

The device flow is recommended as it:
- Works on headless/remote systems
- Doesn't require manual credential setup
- Provides the simplest user experience

Examples:
  waybar-calendar-notify auth                    # Simple authentication
  waybar-calendar-notify auth --status           # Check auth status
  waybar-calendar-notify auth --revoke           # Revoke authentication`,
	RunE: runAuth,
}

func init() {
	authCmd.Flags().BoolVar(&revokeFlag, "revoke", false, "revoke current authentication")
	authCmd.Flags().BoolVar(&statusOnly, "status", false, "check authentication status only")
	authCmd.Flags().BoolVar(&useDeviceFlow, "device-flow", false, "force device flow authentication")
	authCmd.Flags().BoolVar(&useLocalServer, "local-server", false, "force local server authentication")
	authCmd.Flags().StringVar(&customCredFile, "custom-creds", "", "path to custom credentials JSON file")
}

func runAuth(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Determine authentication flow
	flow := calendar.AuthFlowAuto
	if useDeviceFlow {
		flow = calendar.AuthFlowDeviceCode
	} else if useLocalServer {
		flow = calendar.AuthFlowLocalServer
	}

	// Setup auth options
	opts := &calendar.AuthOptions{
		Flow:     flow,
		CredPath: customCredFile,
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

	// Handle revoke
	if revokeFlag {
		fmt.Printf("%s Revoking authentication...\n", nerdfonts.InfoCircle)
		if err := authManager.RevokeToken(ctx); err != nil {
			return fmt.Errorf("failed to revoke token: %w", err)
		}
		fmt.Printf("%s Authentication revoked successfully\n", nerdfonts.CheckCircle)
		return nil
	}

	// Check current authentication status
	if authManager.HasValidToken() {
		fmt.Printf("%s Already authenticated with Google Calendar\n", nerdfonts.CheckCircle)
		fmt.Println("Use --revoke to re-authenticate or --status to check status")
		return nil
	}

	// Perform authentication
	if flow == calendar.AuthFlowDeviceCode {
		fmt.Printf("%s Starting simplified authentication...\n", nerdfonts.InfoCircle)
	} else {
		fmt.Printf("%s Starting authentication flow...\n", nerdfonts.InfoCircle)
		fmt.Println("This will open your browser to complete Google Calendar authorization.")
		fmt.Println("If the browser doesn't open automatically, please copy and paste the URL manually.")
		fmt.Println()
	}

	// Create a temporary calendar client to trigger auth flow
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