# NetShaper - Network Traffic Management Tool

NetShaper is a **Windows-only** network management application that allows users to control bandwidth usage for devices on their local network. Built with Electron, React, TypeScript, and C++ for high-performance network operations.

## Project Status

**Stage 3A COMPLETE** - Device discovery fully operational with responsive UI

### Working Features
- **Fast Device Discovery**: Instantly scans local network using Windows ARP table without UI blocking
- **Async DNS Resolution**: Optional background name resolution using Node.js async DNS 
- **Real-Time Streaming**: Devices appear immediately with progressive name updates
- **Professional UI**: Material UI interface with device listing and progress tracking
- **Responsive Experience**: UI remains interactive during all network operations
- **Universal Compatibility**: Dynamic DNS resolution works on any user's network

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
3. **Scan Network**: Click "Scan Network" button to discover devices instantly
4. **Resolve Names**: Click "Resolve Names" button to get device hostnames
5. **View Results**: Devices appear immediately with names updating in real-time


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
- **Node.js Async DNS**: Non-blocking DNS resolution using dns.reverse()
- **WinDivert**: Packet interception library (included, ready for traffic control)

### Security Features
- **Context Isolation**: Secure renderer process with no Node.js access
- **IPC Communication**: Safe main ↔ renderer messaging with type safety
- **Administrator Validation**: Required privileges detection and warnings
- **Local Operation**: No external network connections or telemetry

## Current Capabilities

### Fully Working
- **Fast Device Discovery**: Instant ARP table scanning with zero UI blocking
- **Smart Filtering**: Removes multicast/broadcast addresses and duplicates automatically
- **Async DNS Resolution**: Background name resolution using Node.js async DNS
- **Real-Time Updates**: Devices appear immediately with names updating progressively
- **Professional UI**: Material UI with device cards and responsive interactions
- **Universal Compatibility**: Dynamic DNS works on any network configuration
- **Debug Infrastructure**: Comprehensive logging for troubleshooting

### Ready for Next Phase
- **Traffic Control Implementation**: Core infrastructure ready for bandwidth limiting
- **Device Management**: Foundation in place for device control features
- **Settings System**: Architecture supports user preferences and persistence

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
```
```

## Roadmap

### Stage 3B - Traffic Control Interface (Next Phase)
- **Device Control UI**: Add bandwidth limit sliders and block buttons to device cards
- **Context Menus**: Implement right-click device management options
- **Custom Nicknames**: Add persistent device naming and storage system
- **Settings Panel**: Create preferences and configuration interface

### Stage 3C - Traffic Control Implementation
- **WinDivert Integration**: Implement actual packet filtering and bandwidth limiting
- **Real-time Monitoring**: Add live bandwidth usage tracking
- **Rule Persistence**: Save and restore traffic control settings

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

**Current Status**: Device discovery phase complete with responsive UI and dynamic DNS resolution. Ready to implement traffic control interface and functionality.