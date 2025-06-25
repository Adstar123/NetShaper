// TypeScript interfaces for NetShaper network operations

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
}

// Application settings interface
export interface AppSettings {
  persistTrafficControls: boolean;
  autoScanInterval: number; // seconds
  showOfflineDevices: boolean;
  theme: 'light' | 'dark' | 'auto';
}

// Custom device nickname interface
export interface DeviceNickname {
  mac: string;
  nickname: string;
  dateAdded: number;
}