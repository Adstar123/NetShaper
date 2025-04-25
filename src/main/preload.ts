// Preload script
// This script runs in a context that has access to both the Electron API
// and the DOM. It will be enhanced in later stages to bridge between 
// main and renderer processes.

window.addEventListener('DOMContentLoaded', () => {
    console.log('DOM content loaded');
    
    // Here we'll eventually expose Electron APIs to the renderer process
    // and set up IPC communication for network operations
  });