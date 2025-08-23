# waybar-calendar-notify

A CLI tool that integrates Google Calendar with Waybar, providing real-time calendar information in your status bar and desktop notifications for upcoming events.

## Features

- Secure OAuth 2.0 device flow authentication
- Output calendar data in Waybar JSON format with tooltips
- Send desktop notifications for upcoming events
- Cache events locally for performance
- Support for multiple output formats (JSON, text)
- Requires your own Google OAuth credentials

## Authentication

This app uses **Google OAuth 2.0 Device Flow** for secure authentication. You must provide your own Google OAuth client credentials.

### Setting Up Google OAuth Credentials

1. **Create or Select Google Cloud Project**:
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select an existing one

2. **Enable Google Calendar API**:
   - Go to [API Library](https://console.developers.google.com/apis/library)
   - Search for "Google Calendar API" and click on it
   - Click "Enable" button

3. **Configure OAuth Consent Screen** (first time only):
   - Go to "APIs & Services" → "OAuth consent screen"
   - Choose "External" user type
   - Fill in Application name (e.g., "Personal Calendar Notify")
   - Add your email in required fields
   - Click "Save and Continue"

4. **Create OAuth Client ID**:
   - Go to "APIs & Services" → "Credentials"
   - Click "Create Credentials" → "OAuth client ID"
   - Choose "TV and Limited-Input devices" as application type
   - Enter a name (e.g., "waybar-calendar-notify")
   - Click "Create"

5. **Download Credentials**:
   - **Important**: Download the JSON file immediately (you can only see the client secret once)
   - Open the downloaded JSON file
   - Copy the `client_id` and `client_secret` values
   - Create `.env` file in project directory with:
     ```
     WAYBAR_GCAL_CLIENT_ID=your_client_id_here
     WAYBAR_GCAL_CLIENT_SECRET=your_client_secret_here
     ```

### First Time Setup
1. Run: `waybar-calendar-notify auth`
2. Visit the URL shown and enter the code displayed
3. Authorize the app in your browser with your Google account
4. That's it! The app will securely store your tokens locally

### Security
- Uses OAuth 2.0 Device Flow (RFC 8628) - the same method used by major CLI tools
- OAuth credentials are embedded at build time from your environment
- Tokens are encrypted and stored locally with restrictive permissions
- Requires your own Google Cloud OAuth client for personal use

## Installation

### Build from Source

```bash
# Clone repository
git clone https://github.com/bnema/waybar-calendar-notify.git
cd waybar-calendar-notify

# Create .env file with your Google OAuth credentials (required)
echo "WAYBAR_GCAL_CLIENT_ID=your_client_id_here" > .env
echo "WAYBAR_GCAL_CLIENT_SECRET=your_client_secret_here" >> .env

# Build locally with credentials from .env
make build-local

# Or build for production with credentials as environment variables
WAYBAR_GCAL_CLIENT_ID=your_id WAYBAR_GCAL_CLIENT_SECRET=your_secret make build
```

## Usage

### Authentication

```bash
# Authenticate with Google Calendar
./bin/waybar-calendar-notify auth

# Check authentication status
./bin/waybar-calendar-notify auth --status

# Clear local authentication (forces re-auth)
./bin/waybar-calendar-notify auth --revoke
```

### Sync Calendar

```bash
# Basic sync and Waybar output
./bin/waybar-calendar-notify sync

# Output as plain text
./bin/waybar-calendar-notify sync --format=text

# Enable notifications for upcoming events
./bin/waybar-calendar-notify sync --notify-upcoming

# Output without tooltip
./bin/waybar-calendar-notify sync --no-tooltip
```

### Other Commands

```bash
# List available calendars
./bin/waybar-calendar-notify calendars

# Check status
./bin/waybar-calendar-notify status
```

## Waybar Configuration

Add to your Waybar config:

```json
{
  "custom/calendar": {
    "exec": "/path/to/waybar-calendar-notify sync",
    "interval": 300,
    "return-type": "json",
    "format": "{icon} {text}",
    "format-icons": ["📅"],
    "tooltip": true
  }
}
```

## Systemd Service (Optional)

Create `/etc/systemd/user/waybar-calendar-notify.service`:

```ini
[Unit]
Description=Waybar Calendar Notifications
After=network-online.target

[Service]
Type=simple
ExecStart=/path/to/waybar-calendar-notify sync --notify-upcoming
Restart=always
RestartSec=300

[Install]
WantedBy=default.target
```

Enable and start:

```bash
systemctl --user enable waybar-calendar-notify.service
systemctl --user start waybar-calendar-notify.service
```

## Configuration

The tool uses these configuration files:
- `~/.config/waybar-calendar-notify/config.yaml` - Main configuration
- `~/.cache/waybar-calendar-notify/token.enc` - Encrypted OAuth tokens (auto-generated securely)

## Development

```bash
# Run linter
make lint

# Format code
make fmt

# Run go vet
make vet

# Run all checks (format, vet, lint)
make check
```

## License

MIT License

Copyright (c) 2024

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.