# NetShaper - Network Traffic Management Tool

NetShaper is a **Windows-only** network management application that allows users to control bandwidth usage for devices on their local network. Built with Electron, React, TypeScript, and C++ for high-performance network operations.

## Project Status

### Working Features
- **Fast Device Discovery**: Instantly scans local network using Windows ARP table
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
3. **Select Network Adapter**: Please select what network adapter you got for correct ARP poisoning implementation
4. **Scan Network**: Click "Scan Network" button to discover devices instantly
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
- **npcap**: Packet interception library (included, ready for traffic control)

### Security Features
- **Context Isolation**: Secure renderer process with no Node.js access
- **IPC Communication**: Safe main ↔ renderer messaging with type safety
- **Administrator Validation**: Required privileges detection and warnings
- **Local Operation**: No external network connections or telemetry

