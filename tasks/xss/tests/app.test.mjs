import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, rm, readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, dirname, resolve, basename} from 'node:path';
import {once} from 'node:events';
import {createForum, COOKIE} from '../app/server.js';
import {BOT_NAME, Store, SESSION_TTL, MEMES} from '../app/store.js';

const password = 'normal_bot_fixture_password_' + 'x'.repeat(32);
const flag = 'KB2CTF{test_fixture}';

async function fixture(run) {
  const directory = await mkdtemp(join(tmpdir(), 'kb2ctf-xss-test-'));
  let now = Date.now();
  const {app, store} = await createForum({directory, botPassword: password, flag, clock: () => now});
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const base = 'http://127.0.0.1:' + server.address().port;
  let cookie = '';
  const get = path => fetch(base + path, {headers: {Cookie: cookie}, redirect: 'manual'});
  const post = (path, values) => fetch(base + path, {method: 'POST',
    headers: {Cookie: cookie}, body: new URLSearchParams(values), redirect: 'manual'});
  const login = async (username = 'alice') => {
    const response = await post('/login', {username, password: 'normal-password'});
    assert.equal(response.status, 303);
    cookie = response.headers.get('set-cookie').split(';')[0];
    return response;
  };
  try {
    await run({store, directory, get, post, login, setCookie: value => {cookie = value;}, advance: value => {now += value;}});
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    assert.ok(basename(directory).startsWith('kb2ctf-xss-test-'));
    await rm(directory, {recursive: true, force: true});
  }
}

test('accounts, opaque session, private profile and logout', async () => fixture(async f => {
  assert.equal((await f.get('/profile')).status, 302);
  assert.equal((await f.post('/posts', {memeId: 'cat', caption: 'Normal meme'})).status, 401);
  assert.equal((await f.post('/register', {username: BOT_NAME, password: 'normal-password'})).status, 400);
  assert.equal((await f.post('/register', {username: 'alice', password: 'normal-password'})).status, 303);
  assert.equal((await f.post('/register', {username: 'alice', password: 'normal-password'})).status, 409);
  assert.equal((await f.post('/login', {username: 'alice', password: 'wrong-password'})).status, 401);
  const response = await f.login();
  const cookie = response.headers.get('set-cookie');
  assert.match(cookie, new RegExp(COOKIE + '=[a-f0-9]{64}'));
  assert.match(cookie, /SameSite=Strict/);
  assert.doesNotMatch(cookie, /HttpOnly/i);
  assert.deepEqual(await (await f.get('/api/me')).json(), {authenticated: true, username: 'alice'});
  assert.ok(!(await (await f.get('/profile')).text()).includes(flag));
  assert.ok(!JSON.stringify(f.store.state).includes(cookie.split(';')[0].split('=')[1]));
  // Trusted server fixture tests authorization only, without capturing a browser session.
  const bot = f.store.state.users.find(user => user.bot);
  f.setCookie(COOKIE + '=' + await f.store.sessionFor(bot));
  assert.ok((await (await f.get('/profile')).text()).includes(flag));
  assert.equal((await f.post('/logout', {})).status, 303);
  assert.equal((await f.get('/api/me')).status, 401);
}));

test('saved benign formatting in both fields, escaped authors and restart persistence', async () => fixture(async f => {
  const name = 'alice<em>';
  assert.equal((await f.post('/register', {username: name, password: 'normal-password'})).status, 303);
  await f.login(name);
  const response = await f.post('/posts', {memeId: 'cat', caption: '<strong>Учебная подпись</strong>'});
  assert.equal(response.status, 303);
  const id = f.store.state.posts.at(-1).id;
  assert.equal((await f.post('/posts/' + id + '/comments', {body: '<em>Обычный комментарий</em>'})).status, 303);
  const html = await (await f.get('/')).text();
  assert.ok(html.includes('<strong>Учебная подпись</strong>'));
  assert.ok(html.includes('<em>Обычный комментарий</em>'));
  assert.ok(html.includes('alice&lt;em&gt;'));
  assert.ok(!html.includes('<strong>alice<em>'));
  const reopened = await Store.open(f.directory, password);
  assert.equal(reopened.state.posts.at(-1).comments[0].body, '<em>Обычный комментарий</em>');
  assert.equal(reopened.state.users.length, 2);
  for (const meme of MEMES) {
    const asset = await f.get('/assets/memes/' + meme.file);
    assert.equal(asset.status, 200);
    assert.match(asset.headers.get('content-type'), /^image\/png/);
  }
}));

test('expiry, request validation and concurrent registration', async () => fixture(async f => {
  const results = await Promise.all([1, 2].map(() => f.post('/register', {username: 'alice', password: 'normal-password'})));
  assert.deepEqual(results.map(response => response.status).sort(), [303, 409]);
  await f.login();
  assert.equal((await f.post('/posts', {memeId: 'unknown', caption: 'Normal'})).status, 400);
  assert.equal((await f.post('/posts', {memeId: 'cat', caption: ''})).status, 400);
  assert.equal((await f.post('/posts/missing/comments', {body: 'Normal'})).status, 404);
  f.advance(SESSION_TTL + 1);
  assert.equal((await f.get('/api/me')).status, 401);
  assert.equal((await f.get('/profile')).status, 302);
  const state = JSON.parse(await readFile(join(f.directory, 'state.json'), 'utf8'));
  assert.ok(state.users.every(user => /^[a-f0-9]{32}:[a-f0-9]{128}$/.test(user.passwordHash)));
}));
