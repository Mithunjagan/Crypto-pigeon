const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('pigeonSetup', Object.freeze({
  connect: address => ipcRenderer.invoke('configure-relay', address)
}));
