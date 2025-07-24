import React, { useState } from 'react';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import Box from '@mui/material/Box';
import AppBar from '@mui/material/AppBar';
import Toolbar from '@mui/material/Toolbar';
import Typography from '@mui/material/Typography';
import Container from '@mui/material/Container';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Chip from '@mui/material/Chip';
import NetworkScanIcon from '@mui/icons-material/Wifi';
import SecurityIcon from '@mui/icons-material/Security';
import StopIcon from '@mui/icons-material/Stop';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import { DeviceInfo, NetworkAdapter } from '../common/types';
import AdapterSelector from './components/AdapterSelector';
import { AdapterProvider, useAdapterActions } from './contexts/AdapterContext';

// Create a theme instance
const theme = createTheme({
  palette: {
    primary: {
      main: '#2196f3',
    },
    secondary: {
      main: '#f50057',
    },
    background: {
      default: '#f5f5f5',
      paper: '#ffffff',
    },
  },
});

const AppContent: React.FC = () => {
  const { disableActions, isAdapterReady } = useAdapterActions();
  const [scanning, setScanning] = useState(false);
  const [resolvingNames, setResolvingNames] = useState(false);
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [foundCount, setFoundCount] = useState(0);
  const [poisonedDevices, setPoisonedDevices] = useState<Set<string>>(new Set());
  
  // Set up event listeners for streaming
  React.useEffect(() => {
    // Listen for individual devices
    const removeDeviceListener = window.electronAPI.onDeviceFound((device: DeviceInfo) => {
      setDevices(prev => {
        // Check for duplicates based on MAC address
        const exists = prev.some(existingDevice => existingDevice.mac === device.mac);
        if (exists) {
          console.log('Duplicate device skipped:', device.mac);
          return prev;
        }
        console.log('Device found:', device);
        return [...prev, device];
      });
      setFoundCount(prev => prev + 1);
    });
    
    // Listen for device updates (DNS resolved names)
    const removeUpdateListener = window.electronAPI.onDeviceUpdated((updatedDevice: DeviceInfo) => {
      setDevices(prev => {
        return prev.map(device => {
          if (device.mac === updatedDevice.mac) {
            console.log('Device name updated:', updatedDevice.mac, 'from', device.name, 'to', updatedDevice.name);
            return { ...device, name: updatedDevice.name };
          }
          return device;
        });
      });
    });
    
    // Listen for scan completion
    const removeScanListener = window.electronAPI.onScanComplete(() => {
      setScanning(false);
      console.log('Scan complete');
    });
    
    // Listen for async DNS resolution completion
    const removeDnsListener = window.electronAPI.onAsyncDnsComplete(() => {
      setResolvingNames(false);
      console.log('Automatic DNS resolution complete');
    });
    
    // Cleanup event listeners and stop any active poisoning on unmount
    return () => {
      // Stop all active poisoning operations
      poisonedDevices.forEach(async (deviceIp) => {
        try {
          await window.electronAPI.stopArpPoisoning(deviceIp);
        } catch (error) {
          console.error('Error stopping poisoning during cleanup:', error);
        }
      });
      
      // Note: These would need to be implemented in preload.ts to properly remove listeners
      // For now, we'll rely on React's cleanup
    };
  }, []);
  
  // Cleanup: Stop all poisoning operations when component unmounts
  React.useEffect(() => {
    return () => {
      // Stop all active poisoning operations on unmount
      Array.from(poisonedDevices).forEach(async (deviceIp) => {
        try {
          await window.electronAPI.stopArpPoisoning(deviceIp);
          console.log(`Cleanup: Stopped poisoning for ${deviceIp}`);
        } catch (error) {
          console.error('Error stopping poisoning during cleanup:', error);
        }
      });
    };
  }, [poisonedDevices]);
  
  // ARP Poisoning functions
  const handleStartPoisoning = async (device: DeviceInfo) => {
    if (!isAdapterReady) {
      setError('Network adapter not ready. Please initialize an adapter first.');
      return;
    }
    
    try {
      console.log(`Starting ARP poisoning for ${device.name} (${device.ip})`);
      const success = await window.electronAPI.startArpPoisoning(device.ip, device.mac);
      
      if (success) {
        setPoisonedDevices(prev => new Set([...prev, device.ip]));
        console.log(`ARP poisoning started successfully for ${device.ip}`);
      } else {
        setError(`Failed to start ARP poisoning for ${device.name}`);
      }
    } catch (err) {
      console.error('Error starting ARP poisoning:', err);
      setError(`Error starting ARP poisoning for ${device.name}`);
    }
  };
  
  const handleStopPoisoning = async (device: DeviceInfo) => {
    try {
      console.log(`Stopping ARP poisoning for ${device.name} (${device.ip})`);
      const success = await window.electronAPI.stopArpPoisoning(device.ip);
      
      if (success) {
        setPoisonedDevices(prev => {
          const newSet = new Set(prev);
          newSet.delete(device.ip);
          return newSet;
        });
        console.log(`ARP poisoning stopped successfully for ${device.ip}`);
      } else {
        setError(`Failed to stop ARP poisoning for ${device.name}`);
      }
    } catch (err) {
      console.error('Error stopping ARP poisoning:', err);
      setError(`Error stopping ARP poisoning for ${device.name}`);
    }
  };
  
  // Network scan function using streaming with automatic DNS resolution
  const handleScan = async () => {
    setScanning(true);
    setResolvingNames(true); // DNS resolution will happen automatically
    setError(null);
    setDevices([]); // Clear previous results
    setFoundCount(0);
    
    try {
      const success = await window.electronAPI.startStreamingScan();
      if (!success) {
        setError('Failed to start network scan. Make sure the application is running with administrator privileges.');
        setScanning(false);
        setResolvingNames(false);
      }
    } catch (err) {
      console.error('Scan failed:', err);
      setError('Failed to scan network. Make sure the application is running with administrator privileges.');
      setScanning(false);
      setResolvingNames(false);
    }
  };
  
  // Manual DNS resolution function - Use real async DNS resolution
  const handleResolveNames = async () => {
    setResolvingNames(true);
    setError(null);
    
    try {
      // Get devices that need name resolution
      const devicesToResolve = devices.filter(device => device.name === device.ip);
      console.log('Starting async DNS resolution for', devicesToResolve.length, 'devices');
      
      // Start async DNS resolution for all devices
      window.electronAPI.startAsyncDnsResolution(devicesToResolve.map(d => ({ip: d.ip, mac: d.mac})));
      
    } catch (err) {
      console.error('Name resolution failed:', err);
      setError('Failed to resolve device names.');
      setResolvingNames(false);
    }
  };
  
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            NetShaper
            {poisonedDevices.size > 0 && (
              <Chip 
                icon={<SecurityIcon />} 
                label={`${poisonedDevices.size} MITM Active`} 
                color="warning" 
                size="small"
                sx={{ ml: 2 }}
              />
            )}
          </Typography>
          <Button 
            color="inherit" 
            startIcon={<NetworkScanIcon />}
            onClick={handleScan}
            disabled={scanning || resolvingNames || disableActions}
            sx={{ mr: 2 }}
          >
            {scanning ? (resolvingNames ? 'Scanning & Resolving...' : 'Scanning...') : 'Scan Network'}
          </Button>
        </Toolbar>
      </AppBar>
      
      <Container component="main" sx={{ mt: 4, mb: 4, flex: 1 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Welcome to NetShaper
        </Typography>
        <Typography paragraph>
          This application allows you to manage and control network traffic for devices on your local network.
        </Typography>
        
        {/* Network Adapter Selection */}
        <AdapterSelector />
      
        <Typography paragraph sx={{ mt: 3 }}>
          {isAdapterReady 
            ? "Click 'Scan Network' to begin discovering devices. Names will be resolved automatically."
            : "Please select and initialize a network adapter first."}
        </Typography>
        
        {poisonedDevices.size > 0 && (
          <Box sx={{ p: 2, bgcolor: 'warning.light', borderRadius: 1, mb: 2 }}>
            <Typography variant="body2" color="warning.dark">
              ⚠️ <strong>Warning:</strong> {poisonedDevices.size} device(s) are currently being intercepted via ARP poisoning (MITM attack). 
              This is redirecting their traffic through your computer for educational purposes. 
              Click "Stop Poison" to restore normal connectivity.
            </Typography>
          </Box>
        )}
        
        {scanning && (
          <Typography color="primary" sx={{ mb: 2 }}>
            {resolvingNames ? 'Scanning network and resolving names...' : 'Scanning network...'} Found {foundCount} device(s) so far
          </Typography>
        )}
        
        {!scanning && resolvingNames && (
          <Typography color="secondary" sx={{ mb: 2 }}>
            Resolving device names in background...
          </Typography>
        )}
        
        {/* Error display */}
        {error && (
          <Box sx={{ p: 2, bgcolor: 'error.light', color: 'error.contrastText', borderRadius: 1, mb: 2 }}>
            <Typography variant="body2">{error}</Typography>
          </Box>
        )}
        
        {/* Device list */}
        {devices.length > 0 && (
          <Box sx={{ mt: 3 }}>
            <Typography variant="h6" gutterBottom>
              Found {devices.length} device(s):
            </Typography>
            {devices.map((device) => {
              const isPoisoned = poisonedDevices.has(device.ip);
              return (
                <Box key={device.mac} sx={{ 
                  p: 2, 
                  border: 1, 
                  borderColor: isPoisoned ? 'warning.main' : 'divider', 
                  borderRadius: 1, 
                  mb: 1,
                  bgcolor: isPoisoned ? 'warning.light' : 'background.paper',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between'
                }}>
                  <Box sx={{ flex: 1 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                      <Typography variant="subtitle1">{device.name}</Typography>
                      {isPoisoned && (
                        <Chip 
                          icon={<SecurityIcon />} 
                          label="MITM Active" 
                          color="warning" 
                          size="small"
                        />
                      )}
                      <Chip 
                        label={device.isOnline ? 'Online' : 'Offline'} 
                        color={device.isOnline ? 'success' : 'default'} 
                        size="small"
                      />
                    </Box>
                    <Typography variant="body2" color="text.secondary">
                      IP: {device.ip} | MAC: {device.mac}
                    </Typography>
                    {device.vendor && (
                      <Typography variant="body2" color="text.secondary">
                        Vendor: {device.vendor}
                      </Typography>
                    )}
                  </Box>
                  
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    {isPoisoned ? (
                      <Button
                        variant="contained"
                        color="error"
                        startIcon={<StopIcon />}
                        onClick={() => handleStopPoisoning(device)}
                        disabled={!isAdapterReady}
                        size="small"
                      >
                        Stop Poison
                      </Button>
                    ) : (
                      <Button
                        variant="contained"
                        color="warning"
                        startIcon={<PlayArrowIcon />}
                        onClick={() => handleStartPoisoning(device)}
                        disabled={!isAdapterReady || !device.isOnline}
                        size="small"
                      >
                        Start Poison
                      </Button>
                    )}
                  </Box>
                </Box>
              );
            })}
          </Box>
        )}
        
        {/* Show message if scan completed but no devices found */}
        {!scanning && devices.length === 0 && !error && (
          <Typography color="text.secondary" sx={{ mt: 2 }}>
            No devices found. Try running the scan again.
          </Typography>
        )}
      </Container>
      
      <Box component="footer" sx={{ p: 2, bgcolor: 'background.paper' }}>
        <Typography variant="body2" color="text.secondary" align="center">
          NetShaper v0.1.0 - Network Traffic Management Tool
        </Typography>
      </Box>
    </Box>
  );
};

const App: React.FC = () => {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <AdapterProvider>
        <AppContent />
      </AdapterProvider>
    </ThemeProvider>
  );
};

export default App;