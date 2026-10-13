// Trusted infrastructure fixture: ordinary HTTP/WebSocket visits only.
// Nothing is submitted to the forum and no browser session data is collected.
import {chromium} from 'playwright';
import {createServer} from 'node:http';
import {createHash} from 'node:crypto';
import {once} from 'node:events';
import {readFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
import {networkPolicy, protectContext} from '/app/bot/policy.js';
import {ensureSession} from '/app/bot/auth.js';

let allowedHits = 0;
let blockedHits = 0;
let upgrades = 0;
const hook = createServer((_req, res) => {allowedHits += 1; res.end('Trusted hook connectivity fixture');});
hook.on('upgrade', (req, socket) => {
  upgrades += 1;
  const accept = createHash('sha1').update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  socket.on('data', () => socket.end());
});
const blocked = createServer((_req, res) => {blockedHits += 1; res.end('Blocked fixture');});
blocked.on('upgrade', (_req, socket) => {blockedHits += 1; socket.destroy();});
hook.listen(0, '127.0.0.1'); blocked.listen(0, '127.0.0.1');
await Promise.all([once(hook, 'listening'), once(blocked, 'listening')]);
const hookOrigin = 'http://127.0.0.1:' + hook.address().port;
const blockedOrigin = 'http://127.0.0.1:' + blocked.address().port;
const browser = await chromium.launch({headless: true, chromiumSandbox: true, ignoreDefaultArgs: ['--disable-dev-shm-usage']});
try {
  const context = await browser.newContext({serviceWorkers: 'block'});
  await protectContext(context, networkPolicy('http://xss:8080', hookOrigin));
  const page = await context.newPage();
  await page.goto(hookOrigin, {waitUntil: 'domcontentloaded', timeout: 5000});
  assert.match(await page.textContent('body'), /Trusted hook connectivity fixture/);
  const connected = await page.evaluate(url => new Promise(resolve => {
    const socket = new WebSocket(url);
    socket.onopen = () => {socket.close(); resolve(true);};
    socket.onerror = () => resolve(false);
    setTimeout(() => resolve(false), 3000);
  }), hookOrigin.replace('http:', 'ws:') + '/events');
  assert.equal(connected, true);
  const blockedPage = await context.newPage();
  await assert.rejects(blockedPage.goto(blockedOrigin, {timeout: 3000}));
  await blockedPage.close();
  const denied = await page.evaluate(url => new Promise(resolve => {
    const socket = new WebSocket(url);
    socket.onopen = () => {socket.close(); resolve(false);};
    socket.onclose = () => resolve(true);
    socket.onerror = () => resolve(true);
    setTimeout(() => resolve(false), 3000);
  }), blockedOrigin.replace('http:', 'ws:') + '/events');
  assert.equal(denied, true);
  assert.ok(allowedHits > 0 && upgrades > 0);
  assert.equal(blockedHits, 0);
  // Ordinary bot login verifies API cookies are also used by the browser page.
  const password = (await readFile('/run/lab/bot-password.txt', 'utf8')).trim();
  await ensureSession(context.request, 'http://xss:8080', password);
  await page.goto('http://xss:8080/', {waitUntil: 'domcontentloaded', timeout: 5000});
  assert.equal(await page.locator('form[action="/posts"]').count(), 1);
  await page.reload({waitUntil: 'domcontentloaded', timeout: 5000});
  assert.equal(await page.locator('form[action="/posts"]').count(), 1);
  await context.close();
  console.log('Sandbox and HTTP/WebSocket policy PASS');
} finally {
  await browser.close();
  hook.closeAllConnections(); blocked.closeAllConnections();
  hook.close(); blocked.close();
}
