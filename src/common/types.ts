// TypeScript interfaces for NetShaper network operations

// Network adapter information
export interface NetworkAdapter {
  name: string;
  description: string;
  friendlyName: string;
  macAddress: string;
  ipAddress: string;
  subnetMask: string;
  gateway: string;
  isActive: boolean;
  isWireless: boolean;
}

// Network topology information
export interface NetworkTopology {
  localIp: string;
  subnetMask: string;
  gatewayIp: string;
  gatewayMac: string;
  interfaceName: string;
  interfaceMac: string;
  subnetCidr: number;
  isValid: boolean;
}

// ARP performance statistics
export interface ArpPerformanceStats {
  packetsSent: number;
  packetsReceived: number;
  sendErrors: number;
  receiveErrors: number;
  avgSendTimeMs: number;
  avgReceiveTimeMs: number;
}

export interface DeviceInfo {
  ip: string;
  mac: string;
  name: string;
  vendor: string;
  isOnline: boolean;
  lastSeen: number;
  // Optional traffic control properties
  downloadLimit?: number;
  uploadLimit?: number;
  isBlocked?: boolean;
  hasTrafficControl?: boolean;
}

export interface TrafficControl {
  mac: string;
  downloadLimit: number; // Mbps
  uploadLimit: number;   // Mbps
  isBlocked: boolean;
  isActive: boolean;
}

// Network module interface - this represents our C++ native module
export interface NetworkModule {
  // Device discovery functions
  scanDevices(): DeviceInfo[];
  scanDevicesFast(): DeviceInfo[];
  getDeviceDetails(mac: string): DeviceInfo;
  resolveSingleDeviceName(ip: string): string;
  
  // Traffic control functions
  setBandwidthLimit(mac: string, downloadLimit: number, uploadLimit: number): boolean;
  setDeviceBlocked(mac: string, blocked: boolean): boolean;
  removeTrafficControl(mac: string): boolean;
  getActiveControls(): TrafficControl[];
  
  // ARP functionality
  enumerateNetworkAdapters(): NetworkAdapter[];
  initializeArp(adapterName: string): boolean;
  getNetworkTopology(): NetworkTopology;
  sendArpRequest(targetIp: string): boolean;
  getArpPerformanceStats(): ArpPerformanceStats;
  cleanupArp(): void;
}

// Application settings interface
export interface AppSettings {
  persistTrafficControls: boolean;
  autoScanInterval: number; // seconds
  showOfflineDevices: boolean;
  theme: 'light' | 'dark' | 'auto';
  selectedAdapter?: string; // Selected network adapter name
  arpEnabled: boolean; // Whether ARP poisoning is enabled
  performanceMonitoring: boolean; // Whether to show performance stats
}

// Custom device nickname interface
export interface DeviceNickname {
  mac: string;
  nickname: string;
  dateAdded: number;
}