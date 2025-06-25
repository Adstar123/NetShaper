# NetShaper - Network Traffic Management Tool

NetShaper is a **Windows-only** network management application that allows users to control bandwidth usage for devices on their local network. Built with Electron, React, TypeScript, and C++ for high-performance network operations.

## Project Status

**Stage 2 PARTIAL** - Network scanning operational with critical UI issues that need resolution

### Working Features
- **Device Discovery**: Successfully scans local network using Windows ARP table
- **DNS Name Resolution**: Resolves device hostnames (routers, printers, computers, smart devices)
- **Real-Time Streaming**: Devices appear individually as discovered (when UI responsive)
- **Professional UI**: Material UI interface with device listing and progress tracking
- **C++ Backend**: High-performance native network module with comprehensive debug logging

### Critical Issues
- **UI Freezing**: Electron window becomes unresponsive during 1-minute network scan
- **Device Duplication**: Each device appears twice in the final device list
- **Reduced Discovery**: Device count dropped from 38 to 28 after recent filtering improvements

## System Requirements

- **Windows 10 or later**
- **Administrator privileges** (required for network operations)
- **Visual Studio Build Tools 2022** with C++ development tools
- **Node.js 16+**
- **Python 3.7+** (for node-gyp)

## Quick Start

### 1. Clone and Install

```bash
git clone <repository-url>
cd NetShaper
npm install
```

### 2. Build the Native Module

**Important**: Run in Windows PowerShell as Administrator:

```powershell
# Build C++ native module
cd src\native\network
npx node-gyp rebuild
copy build\Release\network.node ..\..\..\build\Release\network.node

# Build Electron application
cd ..\..\..
npm run build
```

### 3. Run NetShaper

```powershell
# Run the application (requires administrator privileges)
npm start
```

**Important**: Right-click on PowerShell and "Run as Administrator" for network operations to work.

## How to Use

1. **Launch as Administrator**: Right-click PowerShell → "Run as Administrator"
2. **Start NetShaper**: `npm start`
3. **Scan Network**: Click "Scan Network" button in the app
4. **View Results**: Devices appear in real-time (when UI responsive)


## Technical Architecture

### Frontend Stack
- **Electron**: Desktop application framework
- **React**: UI library with modern hooks and real-time updates
- **TypeScript**: Type-safe development with full interface definitions
- **Material UI**: Professional component library with responsive design
- **Real-Time Streaming**: Event-driven device discovery with progress tracking

### Backend Stack
- **C++ Native Module**: High-performance network operations using Windows APIs
- **N-API**: Node.js addon interface for secure C++ integration
- **Windows IP Helper API**: ARP table access for device discovery
- **DNS Resolution**: Multiple lookup methods (getnameinfo, gethostbyaddr)
- **WinDivert**: Packet interception library (included, ready for traffic control)

### Security Features
- **Context Isolation**: Secure renderer process with no Node.js access
- **IPC Communication**: Safe main ↔ renderer messaging with type safety
- **Administrator Validation**: Required privileges detection and warnings
- **Local Operation**: No external network connections or telemetry

## Current Capabilities

### Fully Working
- **Device Discovery**: Finds network devices via Windows ARP table scanning
- **Smart Filtering**: Removes multicast/broadcast addresses automatically
- **DNS Name Resolution**: Resolves hostnames for routers, printers, computers
- **Real-Time Updates**: Streaming device discovery with progress counter
- **Professional UI**: Material UI with device cards and status information
- **Debug Infrastructure**: Comprehensive logging for troubleshooting

### Known Issues
- **UI Responsiveness**: Window freezes during network scan (1 minute)
- **Device Duplication**: Each device appears twice in final list
- **Discovery Count**: Some devices missing compared to previous scans
- **Performance**: DNS lookups block main thread despite streaming approach

### In Development
- **UI Threading**: Moving DNS lookups to background to prevent freezing
- **Deduplication**: Fixing duplicate device entries in device list
- **Traffic Control**: Bandwidth limiting and device blocking (next phase)

## Development Commands

```powershell
# Install dependencies
npm install

# Build C++ native module (Windows only, as Administrator)
cd src\native\network
npx node-gyp rebuild
copy build\Release\network.node ..\..\..\build\Release\network.node
cd ..\..\..

# Build Electron application
npm run build

# Run application (production mode)
npm start

# Development mode (if needed)
npm run dev                    # Terminal 1: Start webpack dev server
npm run electron-dev          # Terminal 2: Start Electron
```

## Debug Information

### PowerShell Output (Normal):
```
Network module loaded successfully from: C:\...\build\Release\network.node
DEBUG: Trying to resolve name for IP: 192.168.50.1
DEBUG: DNS lookup success for 192.168.50.1: ZenWiFi_Pro_XT12-BA60 (flag: 0)
DEBUG: Returning device name: ZenWiFi_Pro_XT12-BA60 for IP: 192.168.50.1
```

### Electron Console Output (Issue):
```
Device found: {ip: '192.168.xx.x', mac: 'xxxxxxxx', name: 'ZenWiFi_Pro_XT12-BA60'...}
Device found: {ip: '192.168.xx.x', mac: 'xxxxxxxx', name: 'ZenWiFi_Pro_XT12-BA60'...}
[Each device appears exactly twice]
```

## Roadmap

### Immediate Priorities
1. **Fix UI Freezing**: Implement background threading for DNS lookups
2. **Remove Duplicates**: Investigate and fix device duplication issue
3. **Restore Device Count**: Review filtering to ensure all devices detected

### Stage 3B - Traffic Control (Next)
- **Device Control UI**: Bandwidth limit sliders and block buttons
- **Context Menus**: Right-click device management
- **Custom Nicknames**: Persistent device naming system
- **Settings Panel**: Preferences and configuration options

### Future Enhancements
- **Usage Statistics**: Real-time bandwidth monitoring
- **Scheduled Rules**: Time-based traffic control
- **Device Grouping**: Organize devices by type or location

## Security Notes

- **Administrator Required**: Necessary for Windows network interface access
- **Windows-Specific**: Uses Windows IP Helper and WinDivert APIs exclusively
- **Secure Architecture**: Context isolation prevents renderer access to Node.js
- **No External Connections**: No telemetry or external data transmission
- **Local Operation**: All processing happens on local machine only

## Built-In Dependencies

All major dependencies are included or automatically installed:
- **WinDivert**: Included in project (`src/native/network/lib/WinDivert/`)
- **Material UI**: Installed via npm with professional theming
- **Electron**: Latest stable version with security features
- **TypeScript**: Full type safety across the entire application

## License

MIT License - see LICENSE file for details

---

**Built for Windows network management with modern web technologies and high-performance C++ backend.**

**Current Focus**: Resolving UI freezing and duplication issues to achieve production-ready device discovery before implementing traffic control features.