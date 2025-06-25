import { app, BrowserWindow, Menu, dialog, ipcMain } from 'electron';
import * as path from 'path';
import * as dns from 'dns';
import { promisify } from 'util';
import { NetworkModule, DeviceInfo, TrafficControl } from '../common/types';

let mainWindow: BrowserWindow | null = null;

// Simple check for development mode
const isDevelopment = process.env.NODE_ENV === 'development';

// Check if app is running with administrator privileges
const isAdmin = () => {
  // This is a simple check that will be enhanced in later stages
  // For now, we'll just return a placeholder
  return true;
};

function createWindow() {
  // Create the browser window
  mainWindow = new BrowserWindow({
    width: 1024,
    height: 768,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    },
    title: 'NetShaper',
    show: false, // Don't show until ready
    backgroundColor: '#f5f5f5'
  });

  // Load the index.html
  if (isDevelopment) {
    // First try to load from dev server, fallback to file if that fails
    mainWindow.loadURL('http://localhost:9000').catch(() => {
      console.log('Dev server not available, loading from file...');
      if (mainWindow) {
        mainWindow.loadFile(path.join(__dirname, 'index.html'));
      }
    });
    // Open DevTools in development mode
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile(path.join(__dirname, 'index.html'));
  }

  // Show window when ready to prevent flickering
  mainWindow.on('ready-to-show', () => {
    mainWindow?.show();
  });

  // Check for admin privileges and show warning if needed
  if (!isAdmin()) {
    dialog.showMessageBox(mainWindow, {
      type: 'warning',
      title: 'Administrator Privileges Required',
      message: 'NetShaper requires administrator privileges to function properly. Some features may not work correctly.',
      buttons: ['Continue Anyway', 'Quit'],
      defaultId: 0
    }).then(result => {
      if (result.response === 1) {
        app.quit();
      }
    });
  }

  // Emitted when the window is closed
  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // Create application menu
  createMenu();
}

function createMenu() {
  const template: Electron.MenuItemConstructorOptions[] = [
    {
      label: 'File',
      submenu: [
        { role: 'quit' }
      ]
    },
    {
      label: 'Edit',
      submenu: [
        { role: 'cut' },
        { role: 'copy' },
        { role: 'paste' }
      ]
    },
    {
      label: 'View',
      submenu: [
        { role: 'reload' },
        { role: 'toggleDevTools' },
        { type: 'separator' },
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' }
      ]
    },
    {
      label: 'Help',
      submenu: [
        {
          label: 'About NetShaper',
          click() {
            dialog.showMessageBox({
              title: 'About NetShaper',
              message: 'NetShaper v0.1.0\nA network traffic management tool.',
              buttons: ['OK']
            });
          }
        }
      ]
    }
  ];

  const menu = Menu.buildFromTemplate(template);
  Menu.setApplicationMenu(menu);
}

// This method will be called when Electron has finished
// initialization and is ready to create browser windows.
app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    // On macOS it's common to re-create a window in the app when the
    // dock icon is clicked and there are no other windows open.
    if (mainWindow === null) createWindow();
  });
});

// Quit when all windows are closed
app.on('window-all-closed', () => {
  app.quit();
});

// Load the native network module
let networkModule: NetworkModule | null = null;

// Load the native network module
function loadNetworkModule() {
  const possiblePaths = [
    path.join(__dirname, '../build/Release/network.node'),
    path.join(process.cwd(), 'build/Release/network.node'),
    path.join(process.cwd(), 'dist/build/Release/network.node'),
    path.resolve('./build/Release/network.node'),
    path.resolve('./dist/build/Release/network.node')
  ];

  for (const modulePath of possiblePaths) {
    try {
      console.log('Trying to load network module from:', modulePath);
      
      // Check if file exists first
      const fs = require('fs');
      if (fs.existsSync(modulePath)) {
        // Use eval to prevent webpack from trying to resolve this
        const moduleFunc = eval('require');
        networkModule = moduleFunc(modulePath) as NetworkModule;
        console.log('Network module loaded successfully from:', modulePath);
        return;
      } else {
        console.log('File does not exist at:', modulePath);
      }
    } catch (error) {
      console.log('Failed to load from', modulePath, ':', error instanceof Error ? error.message : String(error));
    }
  }
  
  console.error('Could not load network module from any of the attempted paths');
}

// Try to load the module
try {
  loadNetworkModule();
} catch (error) {
  console.error('Fatal error loading network module:', error);
}

// Handle IPC messages from renderer process
ipcMain.handle('network:scanDevices', async (): Promise<DeviceInfo[]> => {
  if (!networkModule) {
    console.error('Network module not loaded');
    return [];
  }
  
  try {
    return networkModule.scanDevices();
  } catch (error) {
    console.error('Error scanning devices:', error);
    return [];
  }
});

// Background DNS resolution function
async function resolveDeviceNames(devices: any[]) {
  console.log('Starting background DNS resolution for', devices.length, 'devices');
  
  for (const device of devices) {
    try {
      // Use the individual DNS resolution function (much faster)
      const resolvedName = networkModule?.resolveSingleDeviceName(device.ip);
      
      if (resolvedName && resolvedName !== device.name && resolvedName !== device.ip) {
        console.log('Resolved name for', device.ip, ':', resolvedName);
        // Send updated device info if name was resolved
        if (mainWindow) {
          mainWindow.webContents.send('device:updated', {
            ...device,
            name: resolvedName
          });
        }
      }
    } catch (error) {
      console.log('Failed to resolve name for device:', device.mac, error);
    }
    
    // Small delay between DNS lookups to prevent overwhelming the network
    await new Promise(resolve => setTimeout(resolve, 300));
  }
  
  console.log('Background DNS resolution completed');
}

// New streaming scan method
ipcMain.handle('network:startStreamingScan', async (): Promise<boolean> => {
  if (!networkModule) {
    console.error('Network module not loaded');
    return false;
  }
  
  try {
    // Use fast scan first to get devices quickly without DNS resolution
    const devices = networkModule.scanDevicesFast();
    console.log('C++ returned', devices.length, 'devices from fast scan');
    
    // Create a set to track sent devices by MAC address to prevent duplicates
    const sentDevices = new Set<string>();
    const deviceList: any[] = [];
    
    // Send them one by one with delays
    for (let i = 0; i < devices.length; i++) {
      const device = devices[i];
      
      // Skip if we've already sent this device (by MAC address)
      if (sentDevices.has(device.mac)) {
        console.log('Main.ts: Skipping duplicate device:', device.mac);
        continue;
      }
      
      // Mark as sent
      sentDevices.add(device.mac);
      deviceList.push(device);
      
      // Send device to renderer
      if (mainWindow) {
        console.log('Main.ts: Sending device to renderer:', device.ip, device.mac);
        mainWindow.webContents.send('device:found', device);
      }
      
      // Small delay to simulate real-time discovery
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    
    // Signal initial scan complete
    if (mainWindow) {
      mainWindow.webContents.send('scan:complete');
    }
    
    // DISABLED: Background DNS resolution causes UI freezing
    // TODO: Implement true async DNS resolution with worker threads
    // setImmediate(() => {
    //   resolveDeviceNames(deviceList).catch(error => {
    //     console.error('Error in background DNS resolution:', error);
    //   });
    // });
    
    return true;
  } catch (error) {
    console.error('Error in streaming scan:', error);
    return false;
  }
});

// Async DNS resolution using Node.js async DNS (completely non-blocking)
ipcMain.handle('network:startAsyncDnsResolution', async (event, deviceData: Array<{ip: string, mac: string}>): Promise<boolean> => {
  if (!deviceData || deviceData.length === 0) {
    return false;
  }
  
  try {
    console.log('Starting async DNS resolution for', deviceData.length, 'devices');
    
    // Use Node.js async DNS resolution
    const reverseAsync = promisify(dns.reverse);
    
    // Process each device asynchronously without blocking
    const resolveDevice = async (device: {ip: string, mac: string}) => {
      try {
        console.log('Resolving DNS for:', device.ip);
        const hostnames = await reverseAsync(device.ip);
        
        if (hostnames && hostnames.length > 0) {
          let name = hostnames[0];
          // Remove domain suffix if present
          const dotPos = name.indexOf('.');
          if (dotPos !== -1) {
            name = name.substring(0, dotPos);
          }
          
          console.log('DNS resolved:', device.ip, '→', name);
          
          // Send result to renderer with MAC address for matching
          if (mainWindow) {
            mainWindow.webContents.send('device:updated', {
              ip: device.ip,
              mac: device.mac,
              name: name
            });
          }
          
          return { ip: device.ip, mac: device.mac, name, success: true };
        }
      } catch (error) {
        console.log('DNS resolution failed for', device.ip, ':', error instanceof Error ? error.message : String(error));
      }
      
      return { ip: device.ip, mac: device.mac, name: device.ip, success: false };
    };
    
    // Start all DNS resolutions concurrently but with delays
    const resolveWithDelay = async () => {
      for (let i = 0; i < deviceData.length; i++) {
        const device = deviceData[i];
        
        // Don't await - let them run concurrently
        resolveDevice(device);
        
        // Small delay between starting each resolution
        if (i < deviceData.length - 1) {
          await new Promise(resolve => setTimeout(resolve, 100));
        }
      }
      
      // Wait a bit then signal completion
      setTimeout(() => {
        console.log('Async DNS resolution completed');
        if (mainWindow) {
          mainWindow.webContents.send('async-dns:complete');
        }
      }, deviceData.length * 200 + 2000); // Estimate completion time
    };
    
    // Start the resolution process (non-blocking)
    resolveWithDelay();
    
    return true;
  } catch (error) {
    console.error('Error starting async DNS resolution:', error);
    return false;
  }
});

// Manual DNS resolution for a single device (user-triggered)
ipcMain.handle('network:resolveDeviceName', async (event, ip: string): Promise<string> => {
  if (!networkModule) {
    console.error('Network module not loaded');
    return ip;
  }
  
  try {
    const resolvedName = networkModule.resolveSingleDeviceName(ip);
    return resolvedName || ip;
  } catch (error) {
    console.error('Error resolving device name:', error);
    return ip;
  }
});

ipcMain.handle('network:getDeviceDetails', async (event, mac: string): Promise<DeviceInfo | null> => {
  if (!networkModule) {
    console.error('Network module not loaded');
    return null;
  }
  
  try {
    const device = networkModule.getDeviceDetails(mac);
    return Object.keys(device).length > 0 ? device : null;
  } catch (error) {
    console.error('Error getting device details:', error);
    return null;
  }
});

ipcMain.handle('network:setBandwidthLimit', async (event, mac: string, downloadLimit: number, uploadLimit: number): Promise<boolean> => {
  if (!networkModule) {
    console.error('Network module not loaded');
    return false;
  }
  
  try {
    return networkModule.setBandwidthLimit(mac, downloadLimit, uploadLimit);
  } catch (error) {
    console.error('Error setting bandwidth limit:', error);
    return false;
  }
});

ipcMain.handle('network:setDeviceBlocked', async (event, mac: string, blocked: boolean): Promise<boolean> => {
  if (!networkModule) {
    console.error('Network module not loaded');
    return false;
  }
  
  try {
    return networkModule.setDeviceBlocked(mac, blocked);
  } catch (error) {
    console.error('Error setting device blocked:', error);
    return false;
  }
});

ipcMain.handle('network:removeTrafficControl', async (event, mac: string): Promise<boolean> => {
  if (!networkModule) {
    console.error('Network module not loaded');
    return false;
  }
  
  try {
    return networkModule.removeTrafficControl(mac);
  } catch (error) {
    console.error('Error removing traffic control:', error);
    return false;
  }
});

ipcMain.handle('network:getActiveControls', async (): Promise<TrafficControl[]> => {
  if (!networkModule) {
    console.error('Network module not loaded');
    return [];
  }
  
  try {
    return networkModule.getActiveControls();
  } catch (error) {
    console.error('Error getting active controls:', error);
    return [];
  }
});