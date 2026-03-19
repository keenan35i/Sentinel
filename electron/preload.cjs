const { contextBridge, ipcRenderer } = require('electron');

const backendHost = process.env.MAC_SENTINEL_HOST || '127.0.0.1';
const backendPort = process.env.MAC_SENTINEL_PORT || '8765';
const backendUrl = `http://${backendHost}:${backendPort}`;

contextBridge.exposeInMainWorld('macSentinel', {
  backendUrl,
  isPackaged: process.env.NODE_ENV === 'production',
  getAppInfo: () => ipcRenderer.invoke('app/info'),
  openPath: (targetPath) => ipcRenderer.invoke('app/open-path', targetPath),
  chooseArtifacts: (options) => ipcRenderer.invoke('app/choose-artifacts', options || {}),
});
