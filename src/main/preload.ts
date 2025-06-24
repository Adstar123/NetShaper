// Preload script - exposes safe IPC methods to renderer process
import { contextBridge, ipcRenderer } from 'electron';
import { DeviceInfo, TrafficControl } from '../common/types';

// Expose protected methods that allow the renderer process to work with the main process
contextBridge.exposeInMainWorld('electronAPI', {
  // Network operations
  scanDevices: (): Promise<DeviceInfo[]> => ipcRenderer.invoke('network:scanDevices'),
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
      getDeviceDetails: (mac: string) => Promise<DeviceInfo | null>;
      setBandwidthLimit: (mac: string, downloadLimit: number, uploadLimit: number) => Promise<boolean>;
      setDeviceBlocked: (mac: string, blocked: boolean) => Promise<boolean>;
      removeTrafficControl: (mac: string) => Promise<boolean>;
      getActiveControls: () => Promise<TrafficControl[]>;
    }
  }
}