import React, { useState } from 'react';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import Box from '@mui/material/Box';
import AppBar from '@mui/material/AppBar';
import Toolbar from '@mui/material/Toolbar';
import Typography from '@mui/material/Typography';
import Container from '@mui/material/Container';
import Button from '@mui/material/Button';
import NetworkScanIcon from '@mui/icons-material/Wifi';
import { DeviceInfo, NetworkAdapter } from '../common/types';
import AdapterSelector from './components/AdapterSelector';

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

const App: React.FC = () => {
  const [scanning, setScanning] = useState(false);
  const [resolvingNames, setResolvingNames] = useState(false);
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [foundCount, setFoundCount] = useState(0);
  const [selectedAdapter, setSelectedAdapter] = useState<NetworkAdapter | undefined>();
  
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
    
    // Cleanup event listeners on unmount
    return () => {
      // Note: These would need to be implemented in preload.ts to properly remove listeners
      // For now, we'll rely on React's cleanup
    };
  }, []);
  
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
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
        <AppBar position="static">
          <Toolbar>
            <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
              NetShaper
            </Typography>
            <Button 
              color="inherit" 
              startIcon={<NetworkScanIcon />}
              onClick={handleScan}
              disabled={scanning || resolvingNames}
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
          <AdapterSelector 
            onAdapterSelected={setSelectedAdapter}
            selectedAdapter={selectedAdapter}
          />
          
          <Typography paragraph sx={{ mt: 3 }}>
            Click "Scan Network" to begin discovering devices. Names will be resolved automatically.
          </Typography>
          
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
              {devices.map((device) => (
                <Box key={device.mac} sx={{ p: 2, border: 1, borderColor: 'divider', borderRadius: 1, mb: 1 }}>
                  <Typography variant="subtitle1">{device.name}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    IP: {device.ip} | MAC: {device.mac} | Status: {device.isOnline ? 'Online' : 'Offline'}
                  </Typography>
                </Box>
              ))}
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
    </ThemeProvider>
  );
};

export default App;