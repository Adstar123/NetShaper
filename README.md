# NetShaper - Network Traffic Management Tool

NetShaper is a **Windows-only** network management application that allows users to control bandwidth usage for devices on their local network. Built with Electron, React, TypeScript, and C++ for high-performance network operations.

## Project Status

**Stage 2 COMPLETED** - Network backend operational, ready for Stage 3 UI enhancements

## System Requirements

- **Windows 10 or later**
- **Administrator privileges** (required for network operations)
- **Visual Studio Build Tools 2019+** with C++ development tools
- **Node.js 16+**
- **Python 3.7+** (for node-gyp)

## Quick Start

### 1. Clone and Install

```bash
git clone <repository-url>
cd NetShaper
npm install
```

### 2. Build the Application

```bash
# Build C++ native module and Electron app
npm run rebuild
npm run build
```

### 3. Run NetShaper

```bash
# Run the application (requires administrator privileges)
npm start
```

**Important**: Right-click on your terminal/IDE and "Run as Administrator" for network operations to work.

## Current Features

- **Device Discovery**: Scans local network using Windows ARP table
- **Real Device Detection**: Finds connected devices with hostnames
- **Modern UI**: Material UI interface with device listing
- **C++ Backend**: High-performance native network module
- **Secure IPC**: Context-isolated communication between processes

## Built-In Libraries

**WinDivert packet manipulation library is included** - no additional downloads needed!
- `src/native/network/lib/WinDivert/include/windivert.h`
- `src/native/network/lib/WinDivert/x64/WinDivert.lib`
- `src/native/network/lib/WinDivert/x64/WinDivert.dll`


## Dev Commands

```bash
# Install dependencies
npm install

# Build C++ native module
npm run rebuild

# Build Electron application
npm run build

# Run application (production mode)
npm start

# Development mode (if needed)
npm run dev                    # Terminal 1: Start webpack dev server
npm run electron-dev          # Terminal 2: Start Electron
```

## How to Use

1. **Launch as Administrator**: Right-click terminal → "Run as Administrator"
2. **Start NetShaper**: `npm start`
3. **Scan Network**: Click "Scan Network" button in the app
4. **View Devices**: See discovered devices with IP, MAC, and hostname info

## Technical Architecture

### Frontend Stack
- **Electron 35+**: Desktop application framework
- **React 19+**: UI library with hooks
- **TypeScript 5+**: Type-safe development
- **Material UI 7+**: Modern component library
- **Webpack 5+**: Module bundling

### Backend Stack
- **C++ Native Module**: High-performance network operations
- **N-API**: Node.js addon interface
- **Windows IP Helper API**: ARP table access
- **WinDivert**: Packet interception library

### Security Features
- **Context Isolation**: Secure renderer process
- **IPC Communication**: Safe main ↔ renderer messaging
- **No Node Integration**: Renderer process secured

## Known Issues (Being Fixed)

1. **Scan Performance**: Takes ~1 minute (optimisation needed)
2. **Duplicate Devices**: Same device appears multiple times
3. **System Addresses**: Shows multicast/broadcast addresses
4. **DNS Resolution**: Slow hostname lookups

## Roadmap - Stage 3

- **Device Control UI**: Bandwidth limit sliders, block buttons
- **Context Menus**: Right-click device management
- **Custom Nicknames**: Persistent device naming
- **Settings Panel**: Preferences and persistence options
- **Data Optimisation**: Fix duplicates and performance

## Security Notes

- Requires administrator privileges for network interface access
- Uses Windows-specific APIs (IP Helper, WinDivert)
- Secure IPC prevents renderer process from accessing Node.js APIs
- No external network connections or telemetry

## System Dependencies

All major dependencies are included or automatically installed:
-  **WinDivert**: Included in project
-  **Material UI**: Installed via npm
-  **Electron**: Installed via npm
-  **Node-gyp**: Installed via npm


## 📄 License

MIT License - see LICENSE file for details

---

**Built for Windows network management with modern web technologies and high-performance C++ backend.**
