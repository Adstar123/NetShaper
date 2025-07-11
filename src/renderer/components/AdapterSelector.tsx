import React, { useState, useEffect } from 'react';
import {
  Box,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  SelectChangeEvent,
  Typography,
  Alert,
  CircularProgress,
  Card,
  CardContent,
  Chip,
  Grid,
  Button,
  Stack
} from '@mui/material';
import {
  NetworkWifi,
  Cable,
  CheckCircle,
  Error,
  Info,
  Refresh
} from '@mui/icons-material';
import { NetworkAdapter, NetworkTopology, ArpPerformanceStats } from '../../common/types';

interface AdapterSelectorProps {
  onAdapterSelected: (adapter: NetworkAdapter) => void;
  selectedAdapter?: NetworkAdapter;
}

const AdapterSelector: React.FC<AdapterSelectorProps> = ({ onAdapterSelected, selectedAdapter }) => {
  const [adapters, setAdapters] = useState<NetworkAdapter[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [topology, setTopology] = useState<NetworkTopology | null>(null);
  const [performanceStats, setPerformanceStats] = useState<ArpPerformanceStats | null>(null);
  const [arpInitialized, setArpInitialized] = useState(false);

  useEffect(() => {
    loadAdapters();
  }, []);

  useEffect(() => {
    if (selectedAdapter) {
      loadNetworkTopology();
      loadPerformanceStats();
    }
  }, [selectedAdapter]);

  const loadAdapters = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Debug logging
      console.log('window.electronAPI:', window.electronAPI);
      console.log('Available electronAPI methods:', Object.keys(window.electronAPI || {}));
      console.log('getNetworkAdapters type:', typeof window.electronAPI?.getNetworkAdapters);
      
      // Get network adapters from native module
      const adapters = await window.electronAPI.getNetworkAdapters();
      setAdapters(adapters);
      
      // Auto-select first active adapter if none selected
      if (!selectedAdapter && adapters.length > 0) {
        const activeAdapter = adapters.find(a => a.isActive) || adapters[0];
        onAdapterSelected(activeAdapter);
      }
    } catch (err) {
      setError(`Failed to load network adapters: ${err}`);
    } finally {
      setLoading(false);
    }
  };

  const loadNetworkTopology = async () => {
    if (!selectedAdapter) return;
    
    try {
      const topology = await window.electronAPI.getNetworkTopology();
      setTopology(topology);
    } catch (err) {
      console.error('Failed to load network topology:', err);
    }
  };

  const loadPerformanceStats = async () => {
    try {
      const stats = await window.electronAPI.getArpPerformanceStats();
      setPerformanceStats(stats);
    } catch (err) {
      console.error('Failed to load performance stats:', err);
    }
  };

  const handleAdapterChange = async (event: SelectChangeEvent<string>) => {
    const adapterName = event.target.value;
    const adapter = adapters.find(a => a.name === adapterName);
    
    if (adapter) {
      onAdapterSelected(adapter);
      
      // Initialize ARP for the selected adapter
      try {
        const success = await window.electronAPI.initializeArp(adapter.name);
        setArpInitialized(success);
        
        if (success) {
          loadNetworkTopology();
          loadPerformanceStats();
        }
      } catch (err) {
        setError(`Failed to initialize ARP for adapter: ${err}`);
      }
    }
  };

  const handleRefresh = () => {
    loadAdapters();
    if (selectedAdapter) {
      loadNetworkTopology();
      loadPerformanceStats();
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" p={3}>
        <CircularProgress size={24} />
        <Typography variant="body2" ml={2}>Loading network adapters...</Typography>
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error" sx={{ mb: 2 }}>
        {error}
        <Button onClick={handleRefresh} size="small" sx={{ ml: 1 }}>
          Retry
        </Button>
      </Alert>
    );
  }

  return (
    <Box>
      <Card elevation={2} sx={{ mb: 2 }}>
        <CardContent>
          <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
            <Typography variant="h6" component="h2">
              Network Adapter Selection
            </Typography>
            <Button
              onClick={handleRefresh}
              startIcon={<Refresh />}
              size="small"
              variant="outlined"
            >
              Refresh
            </Button>
          </Box>
          
          <FormControl fullWidth sx={{ mb: 2 }}>
            <InputLabel id="adapter-select-label">Select Network Adapter</InputLabel>
            <Select
              labelId="adapter-select-label"
              value={selectedAdapter?.name || ''}
              label="Select Network Adapter"
              onChange={handleAdapterChange}
            >
              {adapters.map((adapter) => (
                <MenuItem key={adapter.name} value={adapter.name}>
                  <Box display="flex" alignItems="center" width="100%">
                    {adapter.isWireless ? <NetworkWifi sx={{ mr: 1 }} /> : <Cable sx={{ mr: 1 }} />}
                    <Box flexGrow={1}>
                      <Typography variant="body1">{adapter.friendlyName}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        {adapter.ipAddress} • {adapter.macAddress}
                      </Typography>
                    </Box>
                    {adapter.isActive && (
                      <Chip 
                        label="Active" 
                        size="small" 
                        color="success" 
                        icon={<CheckCircle />}
                      />
                    )}
                  </Box>
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          {selectedAdapter && (
            <Box>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Selected: {selectedAdapter.friendlyName}
              </Typography>
              
              <Stack direction="row" spacing={1} sx={{ mb: 2 }}>
                <Chip 
                  label={selectedAdapter.isWireless ? "Wireless" : "Ethernet"}
                  size="small"
                  variant="outlined"
                  icon={selectedAdapter.isWireless ? <NetworkWifi /> : <Cable />}
                />
                <Chip 
                  label={selectedAdapter.isActive ? "Active" : "Inactive"}
                  size="small"
                  color={selectedAdapter.isActive ? "success" : "error"}
                  icon={selectedAdapter.isActive ? <CheckCircle /> : <Error />}
                />
                <Chip 
                  label={arpInitialized ? "ARP Ready" : "ARP Not Initialized"}
                  size="small"
                  color={arpInitialized ? "success" : "warning"}
                  icon={<Info />}
                />
              </Stack>
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Network Topology Information */}
      {topology && topology.isValid && (
        <Card elevation={2} sx={{ mb: 2 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Network Topology
            </Typography>
            <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr' }, gap: 2 }}>
              <Box>
                <Typography variant="body2"><strong>Local IP:</strong> {topology.localIp}</Typography>
                <Typography variant="body2"><strong>Subnet:</strong> {topology.localIp}/{topology.subnetCidr}</Typography>
                <Typography variant="body2"><strong>Interface MAC:</strong> {topology.interfaceMac}</Typography>
              </Box>
              <Box>
                <Typography variant="body2"><strong>Gateway IP:</strong> {topology.gatewayIp}</Typography>
                <Typography variant="body2"><strong>Gateway MAC:</strong> {topology.gatewayMac}</Typography>
                <Typography variant="body2"><strong>Subnet Mask:</strong> {topology.subnetMask}</Typography>
              </Box>
            </Box>
          </CardContent>
        </Card>
      )}

      {/* Performance Statistics */}
      {performanceStats && (
        <Card elevation={2}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              ARP Performance Statistics
            </Typography>
            <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr' }, gap: 2 }}>
              <Box>
                <Typography variant="body2"><strong>Packets Sent:</strong> {performanceStats.packetsSent}</Typography>
                <Typography variant="body2"><strong>Packets Received:</strong> {performanceStats.packetsReceived}</Typography>
                <Typography variant="body2"><strong>Send Errors:</strong> {performanceStats.sendErrors}</Typography>
              </Box>
              <Box>
                <Typography variant="body2"><strong>Receive Errors:</strong> {performanceStats.receiveErrors}</Typography>
                <Typography variant="body2"><strong>Avg Send Time:</strong> {performanceStats.avgSendTimeMs.toFixed(2)}ms</Typography>
                <Typography variant="body2"><strong>Avg Receive Time:</strong> {performanceStats.avgReceiveTimeMs.toFixed(2)}ms</Typography>
              </Box>
            </Box>
          </CardContent>
        </Card>
      )}

      {!selectedAdapter && (
        <Alert severity="info" sx={{ mt: 2 }}>
          Please select a network adapter to continue with ARP operations.
        </Alert>
      )}
    </Box>
  );
};

export default AdapterSelector;