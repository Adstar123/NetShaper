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
  
  // Placeholder for network scan function
  const handleScan = () => {
    setScanning(true);
    // In later stages, we'll add actual network scanning here
    setTimeout(() => {
      setScanning(false);
      // For now, we'll just simulate the scan completing after 2 seconds
    }, 2000);
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
          
          {/* In future stages, we'll add the device list and controls here */}
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