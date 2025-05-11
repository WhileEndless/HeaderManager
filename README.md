# Burp Suite Header Manager

A Burp Suite extension that allows you to automatically add or modify HTTP request headers for requests sent through Burp tools.

## Features

- Add or modify HTTP headers in outgoing requests
- Save and manage multiple profiles for different projects
- Persistent settings across Burp Suite sessions
- Selectively enable for specific Burp Suite tools (Proxy, Repeater, Scanner, etc.)
- Option to only modify requests that are in scope
- Enable/disable the extension with a single click

## Installation

1. Download the latest JAR file from the [Releases](https://github.com/WhileEndless/HeaderManager/releases) page
2. Open Burp Suite
3. Go to the "Extensions" tab
4. Click on "Add" in the "Installed" sub-tab
5. Select "Java" as the extension type
6. Select the JAR file you downloaded
7. Click "Next" and the extension will be loaded

## Usage

### Basic Operation

1. Navigate to the "Header Manager" tab in Burp Suite
2. Enable the extension using the checkbox
3. Enter your custom headers in the format `Header-Name: Header-Value` (one per line)
4. Select which Burp tools should use the custom headers
5. Optionally check "In Scope Only" to only modify requests that are in Burp's scope

### Adding Headers

Add your headers in the following format (one per line):
```
X-Custom-Header: CustomValue
User-Agent: Modified-User-Agent
Authorization: Bearer your-token-here
```

The extension will:
- Add the header if it doesn't exist in the request
- Replace the header value if the header already exists

### Profile Management

The extension allows you to save different header configurations as profiles:

1. **Creating a new profile**:
   - Enter a profile name in the "Profile Name" field
   - Configure your headers and settings
   - Click "Save"

2. **Loading a profile**:
   - Select a profile from the dropdown list
   - All settings will be automatically loaded

3. **Deleting a profile**:
   - Select the profile you want to delete
   - Click "Delete"
   - Confirm deletion when prompted

All profiles are automatically saved between Burp Suite sessions.

## Tool Selection

You can choose which Burp Suite tools will have headers modified:

- Proxy
- Repeater
- Scanner
- Intruder
- Spider
- Sequencer
- Decoder
- Comparer
- Extender
- Target

Use the "Select All" and "Deselect All" buttons to quickly configure tool selection.



## Requirements

- Burp Suite Professional or Community (tested with version 2022.x and newer)
- Java 8 or newer

## Building from Source

1. Clone the repository:
   ```
   git clone https://github.com/WhileEndless/HeaderManager.git
   ```

2. Build using your preferred Java build system (e.g., Maven, Gradle, or manual compilation)

3. Load the compiled JAR file into Burp Suite

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.
