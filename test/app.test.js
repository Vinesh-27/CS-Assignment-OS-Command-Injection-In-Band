/**
 * Automated Safety & Structural Test Suite
 * Cyber Security Lab: OS Command Injection (In-band) vs Parameterized Execution
 *
 * Uses Node.js built-in test runner (node:test) and assertions (node:assert/strict).
 * Tests verify application structure, security gating, binding restrictions, and input validation
 * WITHOUT executing exploit payloads.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { app, startServer, HOST } = require('../server');

describe('Security Lab Application & Safety Controls', () => {
  let server;
  let testPort;
  let baseUrl;

  before(async () => {
    // Start server on an ephemeral random high port on 127.0.0.1
    await new Promise((resolve) => {
      server = app.listen(0, '127.0.0.1', () => {
        testPort = server.address().port;
        baseUrl = `http://127.0.0.1:${testPort}`;
        resolve();
      });
    });
  });

  after(async () => {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  // Helper for JSON requests
  async function makeRequest(path, options = {}) {
    const url = `${baseUrl}${path}`;
    const response = await fetch(url, options);
    let body;
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      body = await response.json();
    } else {
      body = await response.text();
    }
    return {
      status: response.status,
      headers: response.headers,
      body
    };
  }

  // --------------------------------------------------------------------------
  // 1. Binding & Hostname Security
  // --------------------------------------------------------------------------
  test('Security Constraint: Default host must be strictly 127.0.0.1', () => {
    assert.equal(HOST, '127.0.0.1', 'HOST constant must be 127.0.0.1');
  });

  test('Security Constraint: startServer must reject non-localhost bindings (e.g. 0.0.0.0)', () => {
    assert.throws(
      () => {
        startServer(3001, '0.0.0.0');
      },
      /Security Violation: Server must only bind to 127.0.0.1/,
      'Server must refuse binding to 0.0.0.0'
    );
  });

  // --------------------------------------------------------------------------
  // 2. HTTP Security Response Headers
  // --------------------------------------------------------------------------
  test('Security Headers: nosniff, DENY, and Content-Security-Policy must be present', async () => {
    const res = await makeRequest('/');
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
    assert.ok(res.headers.get('content-security-policy'), 'CSP header must be present');
  });

  // --------------------------------------------------------------------------
  // 3. API Status & Discovery Endpoint
  // --------------------------------------------------------------------------
  test('API Endpoint: GET /api/status returns platform and lab configuration', async () => {
    const res = await makeRequest('/api/status');
    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'online');
    assert.equal(res.body.host, '127.0.0.1');
    assert.equal(typeof res.body.platform, 'string');
    assert.equal(typeof res.body.isWindows, 'boolean');
    assert.equal(typeof res.body.labMode, 'boolean');
  });

  // --------------------------------------------------------------------------
  // 4. Vulnerable Mode Gating (Default Secured Mode)
  // --------------------------------------------------------------------------
  test('Security Gate: Vulnerable endpoint must return 403 Forbidden when LAB_MODE is not true', async () => {
    // If running in normal mode (LAB_MODE is false or undefined)
    if (process.env.LAB_MODE !== 'true') {
      const res = await makeRequest('/api/ping/vulnerable', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: '127.0.0.1' })
      });

      assert.equal(res.status, 403, 'Vulnerable endpoint must be forbidden in normal mode');
      assert.equal(res.body.success, false);
      assert.ok(res.body.error.includes('DISABLED'), 'Error message must state that vulnerable lab mode is disabled');
    }
  });

  // --------------------------------------------------------------------------
  // 5. Input Validation on Secured Endpoint
  // --------------------------------------------------------------------------
  test('Input Validation: Reject missing or empty target on /api/ping/secured with 400 Bad Request', async () => {
    // Missing body
    const res1 = await makeRequest('/api/ping/secured', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    assert.equal(res1.status, 400);
    assert.equal(res1.body.success, false);

    // Whitespace only
    const res2 = await makeRequest('/api/ping/secured', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: '   ' })
    });
    assert.equal(res2.status, 400);
    assert.equal(res2.body.success, false);
  });

  test('Input Validation: Reject oversized input (> 256 chars) with 400 Bad Request', async () => {
    const oversized = 'a'.repeat(300);
    const res = await makeRequest('/api/ping/secured', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: oversized })
    });
    assert.equal(res.status, 400);
    assert.equal(res.body.success, false);
    assert.ok(res.body.error.includes('maximum allowed length'));
  });

  // --------------------------------------------------------------------------
  // 6. Secured Endpoint Argument-Vector Structure
  // --------------------------------------------------------------------------
  test('Architecture Verification: Secured endpoint reports execFile implementation with argument array', async () => {
    // We send an invalid target string that does not execute anything (e.g., 'invalid.local.test')
    const res = await makeRequest('/api/ping/secured', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'invalid.local.test' })
    });

    assert.equal(res.status, 200);
    assert.equal(res.body.mode, 'secured');
    assert.equal(res.body.implementation, 'child_process.execFile()');
    assert.equal(res.body.shellInvoked, false);
    assert.ok(Array.isArray(res.body.argumentVector), 'argumentVector must be an array');
    assert.ok(res.body.argumentVector.includes('invalid.local.test'), 'Target must be an element in argumentVector');
  });

  // --------------------------------------------------------------------------
  // 7. Static Frontend Assets Serving
  // --------------------------------------------------------------------------
  test('Static Assets: index.html, style.css, and script.js are served correctly', async () => {
    const htmlRes = await makeRequest('/');
    assert.equal(htmlRes.status, 200);
    assert.ok(typeof htmlRes.body === 'string' && htmlRes.body.includes('Network Diagnostic Tool'));

    const cssRes = await makeRequest('/style.css');
    assert.equal(cssRes.status, 200);
    assert.ok(typeof cssRes.body === 'string' && cssRes.body.includes('--bg-terminal'));

    const jsRes = await makeRequest('/script.js');
    assert.equal(jsRes.status, 200);
    assert.ok(typeof jsRes.body === 'string' && jsRes.body.includes('textContent'));
  });

  // --------------------------------------------------------------------------
  // 8. Normal Legitimate Execution Test (TEST 1)
  // --------------------------------------------------------------------------
  test('Legitimate Diagnostic: Normal ping execution with 127.0.0.1 on secured endpoint', async () => {
    const res = await makeRequest('/api/ping/secured', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: '127.0.0.1' })
    });

    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.equal(res.body.mode, 'secured');
    assert.equal(res.body.exitCode, 0, 'Ping to 127.0.0.1 should exit with code 0');
    assert.ok(res.body.stdout.length > 0, 'Ping output should contain stdout');
    assert.ok(
      res.body.stdout.toLowerCase().includes('reply') || res.body.stdout.toLowerCase().includes('bytes'),
      'Output should contain ICMP echo reply indicators'
    );
  });
});

// ----------------------------------------------------------------------------
// Process Lifecycle & Environment Safety Tests
// ----------------------------------------------------------------------------
describe('Process Lifecycle & Security Safety Guards', () => {
  const { execFile } = require('child_process');

  test('Production Guard: Server refuses to start when NODE_ENV=production and LAB_MODE=true', async () => {
    await new Promise((resolve, reject) => {
      execFile(
        process.execPath,
        ['server.js'],
        {
          env: { ...process.env, NODE_ENV: 'production', LAB_MODE: 'true' }
        },
        (error, stdout, stderr) => {
          // Expect process to exit with non-zero exit code
          assert.ok(error, 'Process must exit with an error code');
          assert.equal(error.code, 1, 'Exit code should be 1');
          assert.ok(
            stderr.includes('FATAL SECURITY ALERT') || stderr.includes('Vulnerable lab mode cannot be enabled'),
            'Stderr should warn that lab mode was refused in production'
          );
          resolve();
        }
      );
    });
  });

  test('Lab Mode Startup: Server starts and enables vulnerable endpoint when LAB_MODE=true', async () => {
    await new Promise((resolve, reject) => {
      // Start server on port 3099 in lab mode
      const child = execFile(
        process.execPath,
        ['server.js'],
        {
          env: { ...process.env, LAB_MODE: 'true', PORT: '3099', NODE_ENV: 'development' }
        }
      );

      let stdoutAccum = '';
      let testExecuted = false;

      child.stdout.on('data', async (chunk) => {
        stdoutAccum += chunk.toString();
        if (stdoutAccum.includes('http://127.0.0.1:3099') && !testExecuted) {
          testExecuted = true;
          try {
            // Verify /api/status reports labMode: true
            const statusRes = await fetch('http://127.0.0.1:3099/api/status');
            const statusData = await statusRes.json();
            assert.equal(statusData.labMode, true, 'labMode must be true');

            // Verify vulnerable endpoint accepts legitimate input
            const pingRes = await fetch('http://127.0.0.1:3099/api/ping/vulnerable', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ target: '127.0.0.1' })
            });
            const pingData = await pingRes.json();
            assert.equal(pingRes.status, 200);
            assert.equal(pingData.mode, 'vulnerable');
            assert.equal(pingData.shellInvoked, true);

            child.kill();
          } catch (err) {
            child.kill();
            reject(err);
          }
        }
      });

      child.on('close', () => {
        if (testExecuted) {
          resolve();
        } else {
          reject(new Error('Server exited before test completed. Output: ' + stdoutAccum));
        }
      });

      child.on('error', reject);
    });
  });
});
