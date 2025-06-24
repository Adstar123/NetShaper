// Network service for renderer process - handles IPC communication with main process
import { ipcRenderer } from 'electron';
import { DeviceInfo, TrafficControl } from './types';

/**
 * NetworkService provides a clean interface for the renderer process to interact
 * with the network functionality running in the main process.
 */
export class NetworkService {
  
  /**
   * Scan for devices on the local network
   * @returns Promise<DeviceInfo[]> Array of discovered devices
   */
  static async scanDevices(): Promise<DeviceInfo[]> {
    try {
      return await ipcRenderer.invoke('network:scanDevices');
    } catch (error) {
      console.error('Error in NetworkService.scanDevices:', error);
      return [];
    }
  }

  /**
   * Get detailed information about a specific device
   * @param mac MAC address of the device
   * @returns Promise<DeviceInfo | null> Device information or null if not found
   */
  static async getDeviceDetails(mac: string): Promise<DeviceInfo | null> {
    try {
      return await ipcRenderer.invoke('network:getDeviceDetails', mac);
    } catch (error) {
      console.error('Error in NetworkService.getDeviceDetails:', error);
      return null;
    }
  }

  /**
   * Set bandwidth limits for a device
   * @param mac MAC address of the device
   * @param downloadLimit Download speed limit in Mbps (up to 3 decimal places)
   * @param uploadLimit Upload speed limit in Mbps (up to 3 decimal places)
   * @returns Promise<boolean> True if successful, false otherwise
   */
  static async setBandwidthLimit(mac: string, downloadLimit: number, uploadLimit: number): Promise<boolean> {
    try {
      // Validate input ranges
      if (downloadLimit < 0 || downloadLimit > 1000 || uploadLimit < 0 || uploadLimit > 1000) {
        throw new Error('Bandwidth limits must be between 0 and 1000 Mbps');
      }
      
      // Round to 3 decimal places
      const roundedDownload = Math.round(downloadLimit * 1000) / 1000;
      const roundedUpload = Math.round(uploadLimit * 1000) / 1000;
      
      return await ipcRenderer.invoke('network:setBandwidthLimit', mac, roundedDownload, roundedUpload);
    } catch (error) {
      console.error('Error in NetworkService.setBandwidthLimit:', error);
      return false;
    }
  }

  /**
   * Block or unblock a device from internet access
   * @param mac MAC address of the device
   * @param blocked True to block, false to unblock
   * @returns Promise<boolean> True if successful, false otherwise
   */
  static async setDeviceBlocked(mac: string, blocked: boolean): Promise<boolean> {
    try {
      return await ipcRenderer.invoke('network:setDeviceBlocked', mac, blocked);
    } catch (error) {
      console.error('Error in NetworkService.setDeviceBlocked:', error);
      return false;
    }
  }

  /**
   * Remove all traffic controls for a device
   * @param mac MAC address of the device
   * @returns Promise<boolean> True if successful, false otherwise
   */
  static async removeTrafficControl(mac: string): Promise<boolean> {
    try {
      return await ipcRenderer.invoke('network:removeTrafficControl', mac);
    } catch (error) {
      console.error('Error in NetworkService.removeTrafficControl:', error);
      return false;
    }
  }

  /**
   * Get all active traffic controls
   * @returns Promise<TrafficControl[]> Array of active traffic controls
   */
  static async getActiveControls(): Promise<TrafficControl[]> {
    try {
      return await ipcRenderer.invoke('network:getActiveControls');
    } catch (error) {
      console.error('Error in NetworkService.getActiveControls:', error);
      return [];
    }
  }

  /**
   * Helper method to validate MAC address format
   * @param mac MAC address string
   * @returns boolean True if valid MAC address format
   */
  static isValidMacAddress(mac: string): boolean {
    const macPattern = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
    return macPattern.test(mac);
  }

  /**
   * Helper method to format bandwidth values for display
   * @param mbps Bandwidth in Mbps
   * @returns string Formatted bandwidth string
   */
  static formatBandwidth(mbps: number): string {
    if (mbps === 0) return 'Unlimited';
    if (mbps >= 1000) return `${(mbps / 1000).toFixed(1)} Gbps`;
    if (mbps >= 1) return `${mbps.toFixed(1)} Mbps`;
    return `${(mbps * 1000).toFixed(0)} Kbps`;
  }
}