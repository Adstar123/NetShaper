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
import { DeviceInfo } from '../common/types';

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
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  
  // Network scan function using the native module
  const handleScan = async () => {
    setScanning(true);
    setError(null);
    
    try {
      // Use the exposed electronAPI to scan for devices
      const scannedDevices = await window.electronAPI.scanDevices();
      setDevices(scannedDevices);
      console.log('Found devices:', scannedDevices);
    } catch (err) {
      console.error('Scan failed:', err);
      setError('Failed to scan network. Make sure the application is running with administrator privileges.');
    } finally {
      setScanning(false);
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
              disabled={scanning}
            >
              {scanning ? 'Scanning...' : 'Scan Network'}
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
          <Typography paragraph>
            Click "Scan Network" to begin discovering devices.
          </Typography>
          
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
              {devices.map((device, index) => (
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