package cmd

import (
	"fmt"
	"net/http"
	"os"
	"github.com/spf13/cobra"
	"github.com/bnema/waybar-calendar-notify/internal/calendar"
	"github.com/bnema/waybar-calendar-notify/internal/nerdfonts"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Interactive setup wizard for first-time users",
	Long: `Interactive setup wizard that guides you through the complete setup process.
	
This command guides you through:
- Authentication with Google Calendar using the simplified device flow
- Basic configuration verification
- First calendar sync test
- Next steps recommendations

Perfect for first-time users who want a guided experience.

Examples:
  waybar-calendar-notify setup    # Run the interactive setup wizard`,
	RunE: runSetup,
}

func init() {
	rootCmd.AddCommand(setupCmd)
}

func runSetup(cmd *cobra.Command, args []string) error {
	fmt.Printf("%s Welcome to waybar-calendar-notify!\n\n", nerdfonts.CheckCircle)
	
	fmt.Println("This setup wizard will guide you through:")
	fmt.Println("1. ✅ Authentication with Google Calendar (simplified)")
	fmt.Println("2. 🔧 Configuration verification")
	fmt.Println("3. 📅 First calendar sync test")
	fmt.Println("4. 📖 Next steps and usage tips")
	fmt.Println()
	
	// Check for existing authentication
	authManager, err := calendar.NewAuthManager(cacheDir, nil)
	if err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	
	if authManager.HasValidToken() {
		fmt.Printf("%s Step 1: Authentication - Already authenticated!\n", nerdfonts.CheckCircle)
		fmt.Println("Found existing valid authentication token.")
	} else {
		fmt.Printf("%s Step 1: Authentication\n", nerdfonts.InfoCircle)
		
		// Try relay service first
		relayURL := os.Getenv("WAYBAR_RELAY_URL")
		if relayURL == "" {
			relayURL = "https://waybar-calendar-relay.osc-fr1.scalingo.io"
		}
		
		fmt.Printf("🌐 Checking relay service availability...\n")
		if resp, err := http.Get(relayURL + "/health"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				fmt.Printf("✅ Using relay service for authentication\n")
				fmt.Println("This provides seamless authentication without any setup.")
				fmt.Println()
				
				opts := &calendar.AuthOptions{
					UseRelay: true,
					RelayURL: relayURL,
				}
				
				// Trigger authentication by creating a client
				_, err := calendar.NewClient(cacheDir, opts)
				if err != nil {
					fmt.Printf("⚠️  Relay service authentication failed: %v\n", err)
					fmt.Println("Falling back to device flow...")
					goto fallback
				}
				
				// Verify it worked
				if !authManager.HasValidToken() {
					fmt.Printf("⚠️  Relay authentication completed but token validation failed\n")
					fmt.Println("Falling back to device flow...")
					goto fallback
				}
				
				fmt.Printf("%s Authentication successful!\n\n", nerdfonts.CheckCircle)
				goto authComplete
			}
		}
		
	fallback:
		fmt.Printf("⚠️  Relay service unavailable, using device flow\n")
		fmt.Println("We'll now authenticate with Google Calendar using the device flow.")
		fmt.Println("This requires Google Cloud Console setup.")
		fmt.Println()
		
		// Use device flow for setup
		opts := &calendar.AuthOptions{
			Flow: calendar.AuthFlowDeviceCode,
		}
		
		// Trigger authentication by creating a client
		_, err := calendar.NewClient(cacheDir, opts)
		if err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
		
		// Verify it worked
		if !authManager.HasValidToken() {
			return fmt.Errorf("authentication completed but token validation failed")
		}
		
		fmt.Printf("%s Authentication successful!\n\n", nerdfonts.CheckCircle)
	}
	
authComplete:
	
	// Step 2: Configuration check
	fmt.Printf("%s Step 2: Configuration\n", nerdfonts.InfoCircle)
	fmt.Printf("Cache directory: %s\n", cacheDir)
	fmt.Printf("Configuration: Using defaults (config file support available)\n")
	fmt.Println()
	
	// Step 3: First sync test
	fmt.Printf("%s Step 3: First Sync Test\n", nerdfonts.InfoCircle)
	fmt.Println("Testing calendar connection by fetching today's events...")
	
	client, err := calendar.NewClient(cacheDir, nil)
	if err != nil {
		return fmt.Errorf("failed to create calendar client: %w", err)
	}
	
	events, err := client.GetTodaysEvents()
	if err != nil {
		fmt.Printf("%s Warning: Failed to fetch events: %v\n", nerdfonts.ExclamationTriangle, err)
		fmt.Println("This might be temporary. You can retry with 'waybar-calendar-notify sync'")
	} else {
		fmt.Printf("%s Calendar connection successful!\n", nerdfonts.CheckCircle)
		fmt.Printf("Found %d events for today.\n", len(events))
		
		// Show first few events as example
		if len(events) > 0 {
			fmt.Println("\nExample events:")
			maxShow := 3
			if len(events) < maxShow {
				maxShow = len(events)
			}
			for i := 0; i < maxShow; i++ {
				event := events[i]
				fmt.Printf("  - %s: %s\n", event.GetTimeString(), event.GetShortSummary())
			}
			if len(events) > maxShow {
				fmt.Printf("  ... and %d more events\n", len(events)-maxShow)
			}
		}
	}
	fmt.Println()
	
	// Step 4: Next steps
	fmt.Printf("%s Setup Complete!\n\n", nerdfonts.CheckCircle)
	fmt.Println("🎉 waybar-calendar-notify is now ready to use!")
	fmt.Println()
	fmt.Println("📖 Next steps:")
	fmt.Println("┌─────────────────────────────────────────────────────────────────┐")
	fmt.Println("│ 1. Add to Waybar config:                                       │")
	fmt.Println("│    \"custom/calendar\": {                                        │")
	fmt.Println("│        \"exec\": \"waybar-calendar-notify sync\",                 │")
	fmt.Println("│        \"interval\": 300,                                       │")
	fmt.Println("│        \"format\": \"{}\",                                       │")
	fmt.Println("│        \"return-type\": \"json\"                                 │")
	fmt.Println("│    }                                                            │")
	fmt.Println("│                                                                 │")
	fmt.Println("│ 2. Test the integration:                                        │")
	fmt.Println("│    waybar-calendar-notify sync                                  │")
	fmt.Println("│                                                                 │")
	fmt.Println("│ 3. Check status anytime:                                       │")
	fmt.Println("│    waybar-calendar-notify status                               │")
	fmt.Println("│                                                                 │")
	fmt.Println("│ 4. Enable notifications (optional):                            │")
	fmt.Println("│    waybar-calendar-notify sync --notify-upcoming               │")
	fmt.Println("└─────────────────────────────────────────────────────────────────┘")
	fmt.Println()
	fmt.Printf("%s For help: waybar-calendar-notify --help\n", nerdfonts.InfoCircle)
	fmt.Printf("%s Documentation: Check the README for advanced configuration\n", nerdfonts.InfoCircle)
	
	return nil
}