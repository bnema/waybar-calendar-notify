package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type Config struct {
	Notifications NotificationConfig `mapstructure:"notifications"`
	Display       DisplayConfig      `mapstructure:"display"`
	Calendars     CalendarConfig     `mapstructure:"calendars"`
}

type NotificationConfig struct {
	Enabled       bool  `mapstructure:"enabled"`
	ReminderTimes []int `mapstructure:"reminder_times"`
	IncludeAllDay bool  `mapstructure:"include_all_day"`
}

type DisplayConfig struct {
	MaxTooltipEvents int    `mapstructure:"max_tooltip_events"`
	DateFormat       string `mapstructure:"date_format"`
	ShowLocation     bool   `mapstructure:"show_location"`
	ShowDescription  bool   `mapstructure:"show_description"`
}

type CalendarConfig struct {
	PrimaryOnly bool     `mapstructure:"primary_only"`
	CalendarIDs []string `mapstructure:"calendar_ids"`
}

var defaultConfig = Config{
	Notifications: NotificationConfig{
		Enabled:       true,
		ReminderTimes: []int{15, 5},
		IncludeAllDay: false,
	},
	Display: DisplayConfig{
		MaxTooltipEvents: 10,
		DateFormat:       "15:04",
		ShowLocation:     true,
		ShowDescription:  true,
	},
	Calendars: CalendarConfig{
		PrimaryOnly: true,
		CalendarIDs: []string{},
	},
}

func Load(configPath string) (*Config, error) {
	// Set up viper
	v := viper.New()
	v.SetConfigType("toml")
	v.SetConfigName("config")

	// Set default configuration path
	if configPath == "" {
		configDir, err := getDefaultConfigDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get config directory: %w", err)
		}
		configPath = configDir
	}

	v.AddConfigPath(configPath)
	v.AddConfigPath(".")

	// Set defaults
	setDefaults(v)

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		// If config file doesn't exist, create it with defaults
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			if err := createDefaultConfig(configPath); err != nil {
				return nil, fmt.Errorf("failed to create default config: %w", err)
			}
			// Try to read again after creating
			if err := v.ReadInConfig(); err != nil {
				// If it still fails, just use defaults
				return &defaultConfig, nil
			}
		} else {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	// Unmarshal config
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}

func setDefaults(v *viper.Viper) {
	// Notifications
	v.SetDefault("notifications.enabled", defaultConfig.Notifications.Enabled)
	v.SetDefault("notifications.reminder_times", defaultConfig.Notifications.ReminderTimes)
	v.SetDefault("notifications.include_all_day", defaultConfig.Notifications.IncludeAllDay)

	// Display
	v.SetDefault("display.max_tooltip_events", defaultConfig.Display.MaxTooltipEvents)
	v.SetDefault("display.date_format", defaultConfig.Display.DateFormat)
	v.SetDefault("display.show_location", defaultConfig.Display.ShowLocation)
	v.SetDefault("display.show_description", defaultConfig.Display.ShowDescription)

	// Calendars
	v.SetDefault("calendars.primary_only", defaultConfig.Calendars.PrimaryOnly)
	v.SetDefault("calendars.calendar_ids", defaultConfig.Calendars.CalendarIDs)
}

func createDefaultConfig(configPath string) error {
	// Ensure config directory exists
	if err := os.MkdirAll(configPath, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	configFile := filepath.Join(configPath, "config.toml")

	// Check if config already exists
	if _, err := os.Stat(configFile); err == nil {
		return nil // Already exists
	}

	// Create default config content
	configContent := `# waybar-calendar-notify configuration

[notifications]
enabled = true
reminder_times = [15, 5]  # minutes before event
include_all_day = false

[display]
max_tooltip_events = 10
date_format = "15:04"
show_location = true
show_description = true

[calendars]
primary_only = true  # set to false to use calendar_ids
calendar_ids = []    # specific calendar IDs to watch
`

	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func getDefaultConfigDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(homeDir, ".config", "waybar-calendar-notify"), nil
}

func GetDefaultConfigDir() (string, error) {
	return getDefaultConfigDir()
}