import { app, BrowserWindow, Menu, dialog } from 'electron';
import * as path from 'path';

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
      nodeIntegration: true,
      contextIsolation: false,
      preload: path.join(__dirname, 'preload.js')
    },
    title: 'NetShaper',
    show: false, // Don't show until ready
    backgroundColor: '#f5f5f5'
  });

  // Load the index.html
  if (isDevelopment) {
    mainWindow.loadURL('http://localhost:9000');
    // Open DevTools in development mode
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
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

// Handle IPC messages from renderer process
// We'll add these in later stages