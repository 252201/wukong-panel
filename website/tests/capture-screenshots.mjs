import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execAsync = promisify(exec);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const distDir = path.resolve(__dirname, '../dist');
const outDir = path.resolve(__dirname, 'screenshots');

if (!fs.existsSync(outDir)) {
  fs.mkdirSync(outDir, { recursive: true });
}

const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json'
};

const server = http.createServer((req, res) => {
  let cleanPath = (req.url || '/').split('?')[0];
  if (cleanPath === '/' || cleanPath === '') {
    cleanPath = '/index.html';
  }
  const filePath = path.join(distDir, cleanPath);

  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'application/octet-stream' });
    fs.createReadStream(filePath).pipe(res);
  } else {
    res.writeHead(404);
    res.end('Not Found');
  }
});

const PORT = 5198;
server.listen(PORT, async () => {
  console.log(`Screenshot server listening on http://127.0.0.1:${PORT}`);
  const chromePath = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

  try {
    const flags = '--headless=new --disable-gpu --hide-scrollbars';

    // 1. Desktop Hero
    console.log('Capturing Desktop Hero (1440x900)...');
    await execAsync(`"${chromePath}" ${flags} --window-size=1440,900 --screenshot="${path.join(outDir, '1-desktop-hero.png')}" "http://127.0.0.1:${PORT}/"`);

    // 2. Desktop Sandbox Console
    console.log('Capturing Desktop Sandbox...');
    await execAsync(`"${chromePath}" ${flags} --window-size=1440,900 --screenshot="${path.join(outDir, '2-desktop-sandbox.png')}" "http://127.0.0.1:${PORT}/?only=sandbox"`);

    // 3. Desktop Scrollytelling Stories
    console.log('Capturing Desktop Stories...');
    await execAsync(`"${chromePath}" ${flags} --window-size=1440,900 --screenshot="${path.join(outDir, '3-desktop-stories.png')}" "http://127.0.0.1:${PORT}/?only=stories"`);

    // 4. Desktop Performance Matrix
    console.log('Capturing Desktop Performance Matrix...');
    await execAsync(`"${chromePath}" ${flags} --window-size=1440,900 --screenshot="${path.join(outDir, '4-desktop-performance.png')}" "http://127.0.0.1:${PORT}/?only=performance"`);

    // 7. Desktop Xuan Paper Light Mode
    console.log('Capturing Desktop Light Mode (1440x900)...');
    await execAsync(`"${chromePath}" ${flags} --window-size=1440,900 --screenshot="${path.join(outDir, '7-desktop-hero-light.png')}" "http://127.0.0.1:${PORT}/?theme=light"`);

    // Mobile Captures with CDP Device Metrics Override (Real iPhone 16 Viewport: 390x844)
    console.log('Spawning Chrome for CDP iPhone 16 mobile captures...');
    const { spawn } = await import('node:child_process');
    const cdpPort = 9334;
    const cdpProc = spawn(chromePath, [
      '--headless=new',
      `--remote-debugging-port=${cdpPort}`,
      '--remote-allow-origins=*',
      '--user-data-dir=/tmp/cprofile9334',
      '--disable-gpu',
      '--no-first-run',
      '--no-default-browser-check'
    ]);

    await new Promise(r => setTimeout(r, 1500));
    const targetRes = await fetch(`http://127.0.0.1:${cdpPort}/json/list`);
    const targets = await targetRes.json();
    const pageTarget = targets.find(t => t.type === 'page') || targets[0];

    const ws = new WebSocket(pageTarget.webSocketDebuggerUrl);
    let msgId = 1;
    const sendCDP = (method, params = {}) => new Promise((resolve) => {
      const curId = msgId++;
      const handler = (e) => {
        const data = JSON.parse(e.data);
        if (data.id === curId) {
          ws.removeEventListener('message', handler);
          resolve(data.result);
        }
      };
      ws.addEventListener('message', handler);
      ws.send(JSON.stringify({ id: curId, method, params }));
    });

    await new Promise(r => ws.onopen = r);

    await sendCDP('Emulation.setDeviceMetricsOverride', {
      width: 390,
      height: 844,
      deviceScaleFactor: 2,
      mobile: true
    });

    // 5. Mobile Hero (iPhone 390x844)
    console.log('Capturing Mobile Hero (390x844)...');
    await sendCDP('Page.navigate', { url: `http://127.0.0.1:${PORT}/` });
    await new Promise(r => setTimeout(r, 1200));
    const shotHero = await sendCDP('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync(path.join(outDir, '5-mobile-hero.png'), Buffer.from(shotHero.data, 'base64'));

    // 6. Mobile Sandbox (iPhone 390x844)
    console.log('Capturing Mobile Sandbox (390x844)...');
    await sendCDP('Page.navigate', { url: `http://127.0.0.1:${PORT}/?only=sandbox` });
    await new Promise(r => setTimeout(r, 1000));
    const shotSandbox = await sendCDP('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync(path.join(outDir, '6-mobile-sandbox.png'), Buffer.from(shotSandbox.data, 'base64'));

    // 8. Mobile Light Mode (iPhone 390x844)
    console.log('Capturing Mobile Light Mode (390x844)...');
    await sendCDP('Page.navigate', { url: `http://127.0.0.1:${PORT}/?theme=light` });
    await new Promise(r => setTimeout(r, 1000));
    const shotLight = await sendCDP('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync(path.join(outDir, '8-mobile-hero-light.png'), Buffer.from(shotLight.data, 'base64'));

    ws.close();
    cdpProc.kill();

    console.log('All screenshots captured successfully in:', outDir);
  } catch (err) {
    console.error('Screenshot capture failed:', err);
  } finally {
    server.close();
    process.exit(0);
  }
});
