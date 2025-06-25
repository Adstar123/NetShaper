// Preload script - exposes safe IPC methods to renderer process
import { contextBridge, ipcRenderer } from 'electron';
import { DeviceInfo, TrafficControl } from '../common/types';

// Expose protected methods that allow the renderer process to work with the main process
contextBridge.exposeInMainWorld('electronAPI', {
  // Network operations
  scanDevices: (): Promise<DeviceInfo[]> => ipcRenderer.invoke('network:scanDevices'),
  startStreamingScan: (): Promise<boolean> => ipcRenderer.invoke('network:startStreamingScan'),
  resolveDeviceName: (ip: string): Promise<string> => ipcRenderer.invoke('network:resolveDeviceName', ip),
  startAsyncDnsResolution: (devices: Array<{ip: string, mac: string}>): Promise<boolean> => ipcRenderer.invoke('network:startAsyncDnsResolution', devices),
  
  // Event listeners for streaming
  onDeviceFound: (callback: (device: DeviceInfo) => void) => {
    ipcRenderer.on('device:found', (event, device) => callback(device));
  },
  onDeviceUpdated: (callback: (device: DeviceInfo) => void) => {
    ipcRenderer.on('device:updated', (event, device) => callback(device));
  },
  onScanComplete: (callback: () => void) => {
    ipcRenderer.on('scan:complete', () => callback());
  },
  onAsyncDnsComplete: (callback: () => void) => {
    ipcRenderer.on('async-dns:complete', () => callback());
  },
  getDeviceDetails: (mac: string): Promise<DeviceInfo | null> => ipcRenderer.invoke('network:getDeviceDetails', mac),
  setBandwidthLimit: (mac: string, downloadLimit: number, uploadLimit: number): Promise<boolean> => 
    ipcRenderer.invoke('network:setBandwidthLimit', mac, downloadLimit, uploadLimit),
  setDeviceBlocked: (mac: string, blocked: boolean): Promise<boolean> => 
    ipcRenderer.invoke('network:setDeviceBlocked', mac, blocked),
  removeTrafficControl: (mac: string): Promise<boolean> => 
    ipcRenderer.invoke('network:removeTrafficControl', mac),
  getActiveControls: (): Promise<TrafficControl[]> => ipcRenderer.invoke('network:getActiveControls'),
});

// Type definitions for the exposed API
declare global {
  interface Window {
    electronAPI: {
      scanDevices: () => Promise<DeviceInfo[]>;
      startStreamingScan: () => Promise<boolean>;
      resolveDeviceName: (ip: string) => Promise<string>;
      startAsyncDnsResolution: (devices: Array<{ip: string, mac: string}>) => Promise<boolean>;
      onDeviceFound: (callback: (device: DeviceInfo) => void) => void;
      onDeviceUpdated: (callback: (device: DeviceInfo) => void) => void;
      onScanComplete: (callback: () => void) => void;
      onAsyncDnsComplete: (callback: () => void) => void;
      getDeviceDetails: (mac: string) => Promise<DeviceInfo | null>;
      setBandwidthLimit: (mac: string, downloadLimit: number, uploadLimit: number) => Promise<boolean>;
      setDeviceBlocked: (mac: string, blocked: boolean) => Promise<boolean>;
      removeTrafficControl: (mac: string) => Promise<boolean>;
      getActiveControls: () => Promise<TrafficControl[]>;
    }
  }
}