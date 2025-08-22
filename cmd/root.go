package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	
	"github.com/bnema/waybar-calendar-notify/internal/cache"
	"github.com/bnema/waybar-calendar-notify/internal/config"
	"github.com/bnema/waybar-calendar-notify/internal/logger"
)

var (
	cacheDir string
	verbose  bool
	clientSecretsPath string
	cfgFile  string
	cfg      *config.Config
	
	// Version information
	version    string
	commitHash string
	buildTime  string
)

var rootCmd = &cobra.Command{
	Use:   "waybar-calendar-notify",
	Short: "Google Calendar integration for Waybar with desktop notifications",
	Long: `A CLI tool that integrates Google Calendar with Waybar, providing real-time
calendar information in your status bar and desktop notifications for upcoming events.

waybar-calendar-notify fetches your Google Calendar events, displays them in Waybar
with a rich tooltip, and sends desktop notifications for upcoming meetings and appointments.

Perfect for running as a systemd service to get real-time calendar updates and notifications.`,
}

func Execute() error {
	return rootCmd.Execute()
}

// SetVersionInfo sets the version information for the CLI
func SetVersionInfo(v, commit, buildTimeStr string) {
	version = v
	commitHash = commit
	buildTime = buildTimeStr
	
	// Set version on root command
	rootCmd.Version = fmt.Sprintf("%s (commit: %s, built: %s)", version, commitHash, buildTime)
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cacheDir, "cache-dir", "", "cache directory (default: ~/.cache/waybar-calendar-notify)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.config/waybar-calendar-notify/config.toml)")
	rootCmd.PersistentFlags().StringVar(&clientSecretsPath, "client-secrets", "", "path to client secrets JSON file (default: client_secrets_device_oauth.json)")

	// Add subcommands
	rootCmd.AddCommand(syncCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(authCmd)
}

func initConfig() {
	// Initialize logger with verbose flag
	logger.Init(verbose)

	if cacheDir == "" {
		defaultCacheDir, err := cache.GetDefaultCacheDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting default cache directory: %v\n", err)
			os.Exit(1)
		}
		cacheDir = defaultCacheDir
	}

	// Load configuration
	var err error
	cfg, err = config.Load(cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}
}