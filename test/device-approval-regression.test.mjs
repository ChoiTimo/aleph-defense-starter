import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { createDeviceApprovalHandler } from '../src/device-approval-handler.mjs';
import * as approvalEndpoint from '../api/device-approval.js';

test('the production approval endpoint is a server handler and rejects anonymous requests', async () => {
  assert.equal(typeof approvalEndpoint.default, 'function');
  for (const method of ['GET', 'POST']) {
    const res = { setHeader() {}, status(code) { this.code = code; return this; },
      json(data) { this.data = data; return this; } };
    await approvalEndpoint.default({ method, url: '/api/device-approval', headers: {} }, res);
    assert.equal(res.code, 401);
    assert.equal(res.data.reasonCode, 'login_required');
    assert.equal(res.data.deviceRegistered, false);
  }
});

test('the real page module links against its actual browser dependencies', async () => {
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  const script = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1];
  const dependency = await readFile(new URL('../public/device-approval.js', import.meta.url), 'utf8');
  // Link the unchanged import declarations without executing DOM or login code.
  // This catches missing named exports before the browser starts the page.
  const demoDependency = await readFile(new URL('../public/demo-device-client.js', import.meta.url), 'utf8');
  const operationsDependency = await readFile(new URL('../public/operations-panel.js', import.meta.url), 'utf8');
  const code = `
    import { SourceTextModule } from 'node:vm';
    const page = new SourceTextModule(${JSON.stringify(script)});
    const approval = new SourceTextModule(${JSON.stringify(dependency)});
    const demo = new SourceTextModule(${JSON.stringify(demoDependency)});
    const operations = new SourceTextModule(${JSON.stringify(operationsDependency)});
    await page.link(specifier => {
      if (specifier === '/operations-panel.js') return operations;
      if (specifier === '/demo-device-client.js') return demo;
      if (specifier !== '/device-approval.js') throw new Error('Unexpected dependency');
      return approval;
    });
  `;
  execFileSync(process.execPath, ['--experimental-vm-modules', '--input-type=module', '-e', code],
    { windowsHide: true, stdio: 'pipe', timeout: 10000 });
});

test('repeated approval button requests cannot register a device without an official channel', async () => {
  const handler = createDeviceApprovalHandler({ verifyLogin: async () => ({ userId: 'fixture-a' }) });
  for (const method of ['POST', 'POST', 'GET']) {
    const res = { setHeader() {}, status(code) { this.code = code; return this; },
      json(data) { this.data = data; return this; } };
    await handler({ method, url: '/api/device-approval',
      headers: { authorization: 'fixture-login', 'x-device-registered': 'true', 'x-app-installed': 'true' },
      body: { approved: true, deviceRegistered: true } }, res);
    assert.equal(res.code, 503);
    assert.equal(res.data.state, 'unavailable');
    assert.equal(res.data.deviceRegistered, false);
  }
});
