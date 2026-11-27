# Getting Started with BugTrail

This guide explains how to load and run the BugTrail browser extension on your machine.

## Project Location

```
path/BugTrail/
```

## Installation

**Download the version that is compatible with your device**

### Chrome

1. **Open Chrome Extensions Page**
   - Navigate to `chrome://extensions`
   - Or use menu: **☰ → More tools → Extensions**

2. **Enable Developer Mode**
   - Toggle **Developer mode** in the top-right corner

3. **Load the Extension**
   - Click **Load unpacked**
   - Navigate to and select the `bugtrail-chrome` folder

4. **Verify Installation**
   - You should see BugTrail listed in your extensions
   - Look for the BugTrail icon in your Chrome toolbar

### Firefox

1. **Open Firefox Add-ons Debugging Page**
   - Navigate to `about:debugging`
   - Or use menu: **≡ → More tools → WebExtensions Manifest**

2. **Select This Firefox**
   - Click **This Firefox** on the left sidebar

3. **Load the Extension**
   - Click **Load Temporary Add-on**
   - Navigate to and select the `manifest.json` file from the `bugtrail-firefox` folder

4. **Verify Installation**
   - You should see BugTrail listed in your extensions
   - Look for the BugTrail icon in your Firefox toolbar

## Running the Extension

After loading the extension in your browser:

1. **Click the BugTrail Icon**
   - Located in your browser toolbar (top-right area)

2. **Access the Workspace**
   - Click **Workspace** to open the main interface

3. **Initial Setup**
   - Go to **Settings** to configure:
     - **Scope**: Authorized hosts to monitor
     - **Identities**: Test account labels
   - Grant host permissions when prompted

4. **Start Capturing**
   - Enable capture to monitor network traffic
   - Browse your target application
   - View traffic, endpoints, and identifiers

## Project Structure

- **bugtrail-chrome/** - Chrome extension source
- **bugtrail-firefox/** - Firefox extension source
- **docs/** - File-by-file documentation
- **shared/** - Common utilities between browser versions

## Notes

- **No build required** - This is a vanilla JavaScript extension
- **Firefox caveat** - Temporary add-ons are unloaded when the browser restarts
- **Chrome caveat** - Extension will persist until uninstalled
- Both extensions share the same application code with browser-specific manifests

## Troubleshooting

- **Extension not appearing**: Check that Developer Mode is enabled (Chrome) or that you selected the correct manifest (Firefox)
- **Permission errors**: Grant the requested host permissions when the extension prompts
- **Storage not persisting**: Clear browser cache/storage or reload the extension

For more details, see the [main README](README.md) and the [documentation index](docs/README.md).
