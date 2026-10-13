import test from 'node:test';
import assert from 'node:assert/strict';
import {networkPolicy, runner} from '../bot/policy.js';
import {ensureSession} from '../bot/auth.js';

test('only exact forum and configured hook origins, HTTP and WebSocket', () => {
  const allows = networkPolicy('http://xss:8080', 'http://hook.local:3000');
  for (const url of ['http://xss:8080/', 'http://hook.local:3000/probe', 'ws://hook.local:3000/events']) assert.ok(allows(url));
  for (const url of ['http://other.local/', 'http://hook.local:3001/', 'https://hook.local:3000/', 'file:///tmp/example', 'invalid']) assert.ok(!allows(url));
  assert.ok(!networkPolicy('http://xss:8080')('http://hook.local:3000/'));
});

test('failed visit and overlapping ticks cannot create concurrent visits', async () => {
  let finish;
  const pending = new Promise(resolve => {finish = resolve;});
  const tick = runner(() => pending);
  const first = tick();
  assert.equal(await tick(), false);
  finish();
  assert.equal(await first, true);
  let count = 0;
  const retry = runner(async () => {if (++count === 1) throw new Error('fixture navigation failure');});
  await assert.rejects(retry());
  assert.equal(await retry(), true);
});

test('valid bot session persists, an expired session triggers login', async () => {
  let active = true;
  let logins = 0;
  const request = {
    get: async () => ({status: () => active ? 200 : 401, json: async () => ({username: 'meme-reader'})}),
    post: async (_url, options) => {
      assert.equal(options.form.username, 'meme-reader');
      active = true; logins += 1;
      return {status: () => 303};
    },
  };
  assert.equal(await ensureSession(request, 'http://xss:8080', 'trusted-test-fixture'), false);
  active = false;
  assert.equal(await ensureSession(request, 'http://xss:8080', 'trusted-test-fixture'), true);
  assert.equal(await ensureSession(request, 'http://xss:8080', 'trusted-test-fixture'), false);
  assert.equal(logins, 1);
});
