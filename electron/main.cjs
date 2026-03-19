const { app, BrowserWindow, ipcMain, shell, dialog, session } = require('electron');
const path = require('node:path');
const fs = require('node:fs');
const { spawn } = require('node:child_process');

let mainWindow = null;
let backendProcess = null;
let backendReadyPromise = null;

const isDev = !app.isPackaged;
const enableDevtools = isDev && process.env.MAC_SENTINEL_ENABLE_DEVTOOLS === '1';
const projectRoot = path.resolve(__dirname, '..');
const backendPort = process.env.MAC_SENTINEL_PORT || '8765';
const backendHost = process.env.MAC_SENTINEL_HOST || '127.0.0.1';
const backendUrl = `http://${backendHost}:${backendPort}`;

function resolvePythonExecutable() {
  if (process.env.MAC_SENTINEL_PYTHON) return process.env.MAC_SENTINEL_PYTHON;
  const candidates = [
    path.join(projectRoot, '.venv', 'bin', 'python3'),
    path.join(projectRoot, '.venv', 'bin', 'python'),
    'python3',
    'python',
  ];
  return candidates.find((candidate) => candidate === 'python3' || candidate === 'python' || fs.existsSync(candidate));
}

function resolveBackendCommand() {
  if (app.isPackaged) {
    const resourceRoot = process.resourcesPath;
    const candidates = [
      path.join(resourceRoot, 'backend', 'mac-sentinel-backend'),
      path.join(resourceRoot, 'backend', 'mac-sentinel-backend.exe'),
    ];
    const executable = candidates.find((candidate) => fs.existsSync(candidate));
    if (!executable) {
      throw new Error('Packaged backend executable was not found in the app resources. Run the backend build step before packaging.');
    }
    return { command: executable, args: [] };
  }
  const python = resolvePythonExecutable();
  return { command: python, args: [path.join(projectRoot, 'app.py')] };
}

function waitForBackend(timeoutMs = 25000) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const attempt = async () => {
      try {
        const response = await fetch(`${backendUrl}/api/health`);
        if (response.ok) {
          resolve(true);
          return;
        }
      } catch (_error) {
        // Ignore transient startup failures and retry.
      }
      if (Date.now() - started > timeoutMs) {
        reject(new Error('Timed out waiting for the Python backend to start.'));
        return;
      }
      setTimeout(attempt, 350);
    };
    attempt();
  });
}

function startBackend() {
  if (backendProcess) return backendReadyPromise;
  const { command, args } = resolveBackendCommand();
  backendProcess = spawn(command, args, {
    cwd: projectRoot,
    env: {
      ...process.env,
      PYTHONUNBUFFERED: '1',
      MAC_SENTINEL_PORT: backendPort,
      MAC_SENTINEL_HOST: backendHost,
    },
    stdio: isDev ? 'inherit' : 'ignore',
  });
  backendProcess.on('exit', (code) => {
    backendProcess = null;
    if (code && code !== 0 && mainWindow) {
      dialog.showErrorBox('Mac Sentinel backend stopped', `The Python backend exited with code ${code}.`);
    }
  });
  backendReadyPromise = waitForBackend();
  return backendReadyPromise;
}

function hardenSession() {
  const defaultSession = session.defaultSession;
  defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
  defaultSession.setPermissionCheckHandler(() => false);
}

async function createWindow() {
  await startBackend();
  hardenSession();

  mainWindow = new BrowserWindow({
    width: 1580,
    height: 980,
    minWidth: 1180,
    minHeight: 760,
    title: 'Mac Sentinel',
    autoHideMenuBar: true,
    backgroundColor: '#07111f',
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
    },
  });

  mainWindow.webContents.on('will-navigate', (event, url) => {
    const allowed = url.startsWith('file://') || url.startsWith('devtools://') || url.startsWith(backendUrl);
    if (!allowed) {
      event.preventDefault();
      shell.openExternal(url);
    }
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  const devUrl = process.env.MAC_SENTINEL_DESKTOP_DEV_URL;
  if (isDev && devUrl) {
    await mainWindow.loadURL(devUrl);
    if (enableDevtools) mainWindow.webContents.openDevTools({ mode: 'detach' });
  } else {
    const rendererEntry = path.join(projectRoot, 'dist', 'renderer', 'index.html');
    if (!fs.existsSync(rendererEntry)) {
      const message = [
        '<html><body style="background:#07111f;color:#e5eefc;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;padding:24px;">',
        '<h2>Mac Sentinel renderer not built</h2>',
        '<p>The desktop shell started, but the React renderer files were not found.</p>',
        '<p>Run <code>./launcher.command</code> or <code>npm run build</code> in the project folder, then relaunch.</p>',
        '</body></html>',
      ].join('');
      await mainWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(message)}`);
      return;
    }
    await mainWindow.loadFile(rendererEntry);
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

ipcMain.handle('app/info', () => ({
  name: app.getName(),
  version: app.getVersion(),
  isPackaged: app.isPackaged,
  backendUrl,
}));

ipcMain.handle('app/open-path', async (_event, targetPath) => {
  if (!targetPath) return { ok: false };
  await shell.openPath(targetPath);
  return { ok: true };
});

ipcMain.handle('app/choose-artifacts', async (_event, options = {}) => {
  if (!mainWindow) return [];
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: Array.isArray(options.properties) && options.properties.length
      ? options.properties
      : ['openFile', 'openDirectory', 'multiSelections'],
    filters: Array.isArray(options.filters) ? options.filters : [],
    title: options.title || 'Choose local forensic artifacts',
  });
  if (result.canceled) return [];
  return result.filePaths || [];
});

app.whenReady().then(createWindow).catch((error) => {
  dialog.showErrorBox('Mac Sentinel failed to start', error.message || String(error));
  app.quit();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  if (backendProcess && !backendProcess.killed) {
    backendProcess.kill('SIGTERM');
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});
