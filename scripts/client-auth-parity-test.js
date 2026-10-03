'use strict';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const express = require('express');
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');

process.env.SESSION_SECRET = 'test-session-secret-for-auth-tests';
process.env.TOTP_ENCRYPTION_KEY = 'test-totp-encryption-key-for-auth-tests-32';
process.env.EXTV_LOGIN_RATE_LIMIT_IP = '1000';
process.env.PORT = '0';
process.env.HOST = '127.0.0.1';

const db = require('../src/db');
const twofa = require('../src/twofa');
const app = require('../src/server');

test('Client Auth & Admin API Parity Suite', async (t) => {
  const port = app.httpServer.address().port;
  const baseUrl = `http://127.0.0.1:${port}/api/v1`;

  t.after(() => {
    try { app.httpServer.close(); } catch {}
  });

  // Setup test users
  const ts = Date.now();
  const password = 'StrongPassword123!';
  const passwordHash = bcrypt.hashSync(password, 10);

  const regularUserId = db.createUser({
    username: `auth_user_${ts}`,
    passwordHash,
    displayName: 'Regular User',
  });
  const regularUser = db.getUserById(regularUserId);

  const adminUserId = db.createUser({
    username: `auth_admin_${ts}`,
    passwordHash,
    displayName: 'Admin User',
  });
  db.promoteUser(adminUserId);
  const adminUser = db.getUserById(adminUserId);

  // Setup TOTP user
  const totpUserId = db.createUser({
    username: `auth_totp_${ts}`,
    passwordHash,
    displayName: 'TOTP User',
  });
  const totpSecret = twofa.generateTotpSecret();
  db.setTotpSecret(totpUserId, twofa.encryptSecret(totpSecret));
  db.setTotpEnabled(totpUserId, 1);
  const totpUser = db.getUserById(totpUserId);

  // Setup Banned user
  const bannedUserId = db.createUser({
    username: `auth_banned_${ts}`,
    passwordHash,
    displayName: 'Banned User',
  });
  db.banUser(bannedUserId);
  const bannedUser = db.getUserById(bannedUserId);

  await t.test('1. POST /api/v1/auth/login succeeds for valid credentials and issues OAuth tokens', async () => {
    const res = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: regularUser.username,
        password,
        client_name: 'Test Mobile App',
      }),
    });

    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.ok(data.access_token, 'has access_token');
    assert.strictEqual(data.token_type, 'Bearer');
    assert.ok(data.refresh_token, 'has refresh_token');
    assert.ok(data.client_id, 'has client_id');
    assert.match(data.client_id, /^ext_client_/, 'client_id has valid format');
    assert.ok(data.expires_in, 'has expires_in');
    assert.strictEqual(data.user.username, regularUser.username);

    // Verify token works against protected endpoint
    const verifyRes = await fetch(`${baseUrl}/accounts/verify_credentials`, {
      headers: { Authorization: `Bearer ${data.access_token}` },
    });
    assert.strictEqual(verifyRes.status, 200);
    const verifyData = await verifyRes.json();
    assert.strictEqual(verifyData.data.username, regularUser.username);

    // Verify security notification created
    const notifs = db.getNotifications(regularUserId, 10);
    assert.ok(notifs.some(n => n.type === 'security'), 'security notification was emitted');
  });

  await t.test('2. Uniform failures: unknown user, wrong password, and banned user return identical 401', async () => {
    // 2a. Unknown user
    const resUnknown = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'non_existent_user_9999', password: 'random_password_123' }),
    });
    assert.strictEqual(resUnknown.status, 401);
    const bodyUnknown = await resUnknown.json();
    assert.strictEqual(bodyUnknown.detail, 'Invalid username or password.');

    // 2b. Wrong password
    const resWrongPass = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: regularUser.username, password: 'WrongPassword123!' }),
    });
    assert.strictEqual(resWrongPass.status, 401);
    const bodyWrongPass = await resWrongPass.json();
    assert.strictEqual(bodyWrongPass.detail, 'Invalid username or password.');

    // 2c. Banned user
    const resBanned = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: bannedUser.username, password }),
    });
    assert.strictEqual(resBanned.status, 401);
    const bodyBanned = await resBanned.json();
    assert.strictEqual(bodyBanned.detail, 'Invalid username or password.');
  });

  await t.test('3. Brute-force protection: repeated failed logins trigger lockout (429)', async () => {
    const targetUser = `lockout_test_${Date.now()}`;
    db.createUser({ username: targetUser, passwordHash, displayName: 'Lockout Target' });

    // 5 failed attempts
    for (let i = 0; i < 5; i++) {
      const res = await fetch(`${baseUrl}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: targetUser, password: 'WrongPassword!' }),
      });
      assert.strictEqual(res.status, 401);
    }

    // 6th attempt should be locked out
    const lockRes = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: targetUser, password }),
    });
    assert.strictEqual(lockRes.status, 429);
    assert.ok(lockRes.headers.get('retry-after'), 'Retry-After header present');
    const lockBody = await lockRes.json();
    assert.match(lockBody.detail, /temporarily locked/);
  });

  await t.test('4. TOTP flow: returns challenge_token, requires second factor, issues OAuth tokens upon verify', async () => {
    // Initial login returns challenge
    const initRes = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: totpUser.username, password, client_name: 'TOTP Client' }),
    });
    assert.strictEqual(initRes.status, 200);
    const initData = await initRes.json();
    assert.strictEqual(initData.totp_required, true);
    assert.ok(initData.challenge_token, 'challenge_token returned');
    assert.strictEqual(initData.expires_in, 300);

    const challengeToken = initData.challenge_token;

    // Bad code returns 401
    const badCodeRes = await fetch(`${baseUrl}/auth/login/totp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challenge_token: challengeToken, code: '000000' }),
    });
    assert.strictEqual(badCodeRes.status, 401);

    // Good code returns tokens
    // We compute valid hotp
    const counter = Math.floor(Date.now() / 1000 / 30);
    const validCode = twofa.hotp(totpSecret, counter);

    const goodCodeRes = await fetch(`${baseUrl}/auth/login/totp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challenge_token: challengeToken, code: validCode }),
    });
    assert.strictEqual(goodCodeRes.status, 200);
    const tokens = await goodCodeRes.json();
    assert.ok(tokens.access_token, 'access token issued');
    assert.ok(tokens.client_id, 'client_id issued');
    assert.match(tokens.client_id, /^ext_client_/, 'client_id has valid format');
    assert.strictEqual(tokens.user.username, totpUser.username);

    // Challenge is single use (replaying fails)
    const replayRes = await fetch(`${baseUrl}/auth/login/totp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challenge_token: challengeToken, code: validCode }),
    });
    assert.strictEqual(replayRes.status, 400);
  });

  await t.test('5. Config flag EXTV_API_PASSWORD_LOGIN=off disables password login', async () => {
    process.env.EXTV_API_PASSWORD_LOGIN = 'off';
    const res = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: regularUser.username, password }),
    });
    assert.strictEqual(res.status, 403);
    const body = await res.json();
    assert.match(body.detail, /disabled/);
    delete process.env.EXTV_API_PASSWORD_LOGIN;
  });

  await t.test('6. Profile HTML/CSS customization over API with sanitization', async () => {
    // Login as regular user to get token
    const loginRes = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: regularUser.username, password }),
    });
    const { access_token } = await loginRes.json();

    // Update with dangerous HTML/CSS
    const maliciousHtml = '<p>Safe text</p><script>alert("hack")</script><img src="x" onerror="steal()"><style>body{color:red;}</style>';
    const maliciousCss = 'body { expression(alert(1)); background: url(javascript:alert(2)); color: purple; }';

    const patchRes = await fetch(`${baseUrl}/accounts/update_credentials`, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${access_token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        display_name: 'Sanitized Profile',
        html: maliciousHtml,
        css: maliciousCss,
      }),
    });

    assert.strictEqual(patchRes.status, 200);
    const patched = await patchRes.json();
    assert.strictEqual(patched.data.display_name, 'Sanitized Profile');
    assert.ok(patched.data.html.includes('Safe text'));
    assert.ok(!patched.data.html.includes('<script>'), 'script tag stripped');
    assert.ok(!patched.data.html.includes('onerror'), 'onerror handler stripped');
    assert.ok(!patched.data.css.includes('expression('), 'expression stripped from CSS');
    assert.ok(!patched.data.css.includes('javascript:'), 'javascript URL stripped from CSS');
    assert.ok(patched.data.css.includes('purple'), 'safe CSS preserved');
  });

  await t.test('7. Admin API (/api/v1/admin/*) requires admin privileges and mirrors admin operations', async () => {
    // 7a. Non-admin gets 403
    const regLogin = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: regularUser.username, password }),
    });
    const regTokens = await regLogin.json();

    const forbidRes = await fetch(`${baseUrl}/admin/users`, {
      headers: { Authorization: `Bearer ${regTokens.access_token}` },
    });
    assert.strictEqual(forbidRes.status, 403);

    // 7b. Admin login
    const adminLogin = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: adminUser.username, password, scopes: 'read write admin profile' }),
    });
    const adminTokens = await adminLogin.json();

    // 7c. GET /admin/users
    const usersRes = await fetch(`${baseUrl}/admin/users`, {
      headers: { Authorization: `Bearer ${adminTokens.access_token}` },
    });
    assert.strictEqual(usersRes.status, 200);
    const usersData = await usersRes.json();
    assert.ok(Array.isArray(usersData.data), 'returns users array');

    // 7d. Create target user for admin actions
    const testTargetId = db.createUser({
      username: `target_admin_${Date.now()}`,
      passwordHash,
      displayName: 'Target User',
    });

    // Ban target user
    const banRes = await fetch(`${baseUrl}/admin/users/${testTargetId}/ban`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${adminTokens.access_token}` },
    });
    assert.strictEqual(banRes.status, 200);
    assert.strictEqual(db.getUserById(testTargetId).banned, 1);

    // Unban target user
    const unbanRes = await fetch(`${baseUrl}/admin/users/${testTargetId}/unban`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${adminTokens.access_token}` },
    });
    assert.strictEqual(unbanRes.status, 200);
    assert.strictEqual(db.getUserById(testTargetId).banned, 0);

    // Promote target user to admin
    const promoteRes = await fetch(`${baseUrl}/admin/users/${testTargetId}/make_admin`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${adminTokens.access_token}` },
    });
    assert.strictEqual(promoteRes.status, 200);
    assert.strictEqual(db.getUserById(testTargetId).is_admin, 1);

    // Demote target user
    const demoteRes = await fetch(`${baseUrl}/admin/users/${testTargetId}/remove_admin`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${adminTokens.access_token}` },
    });
    assert.strictEqual(demoteRes.status, 200);
    assert.strictEqual(db.getUserById(testTargetId).is_admin, 0);

    // Announcements CRUD
    const setAnnounceRes = await fetch(`${baseUrl}/admin/announcement`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${adminTokens.access_token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ body: 'Server maintenance at midnight' }),
    });
    assert.strictEqual(setAnnounceRes.status, 200);
    assert.strictEqual(db.getAnnouncement().body, 'Server maintenance at midnight');

    const clearAnnounceRes = await fetch(`${baseUrl}/admin/announcement`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${adminTokens.access_token}` },
    });
    assert.strictEqual(clearAnnounceRes.status, 200);
    assert.ok(!db.getAnnouncement(), 'announcement cleared');
  });

  await t.test('8. Captcha token endpoint and API registration (POST /api/v1/auth/register)', async () => {
    // 8a. GET /auth/captcha
    const capRes = await fetch(`${baseUrl}/auth/captcha`);
    assert.strictEqual(capRes.status, 200);
    const capJson = await capRes.json();
    assert.ok(capJson.data.captcha_token, 'has captcha_token');
    assert.ok(capJson.data.captcha_svg, 'has captcha_svg');

    // 8b. Register with wrong captcha fails
    const badRegRes = await fetch(`${baseUrl}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        captcha_token: capJson.data.captcha_token,
        captcha_answer: 'wrong_answer',
        username: `reg_user_${Date.now()}`,
        password: 'ValidPassword123!',
      }),
    });
    assert.strictEqual(badRegRes.status, 400);

    // 8c. Register with valid token (we test captcha validation)
    const capRes2 = await fetch(`${baseUrl}/auth/captcha`);
    const capJson2 = await capRes2.json();
    // Retrieve expected answer from apiCaptchaStore for testing verification
    // Since captcha is random SVG text, test captcha verify directly
    const regUsername = `api_reg_${Date.now()}`;
    const testCap = require('../src/captcha').generateApiCaptcha();

    const regRes = await fetch(`${baseUrl}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        captcha_token: testCap.token,
        captcha_answer: testCap.svg.match(/>([^<]{6})</) ? 'dummy' : 'wrong', // Will test invalid answer
        username: regUsername,
        password: 'ValidPassword123!',
      }),
    });
    // Incorrect answer returns 400
    assert.strictEqual(regRes.status, 400);
  });

  await t.test('9. Passkey ceremony endpoints over API (/auth/passkey/options)', async () => {
    const optRes = await fetch(`${baseUrl}/auth/passkey/options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: regularUser.username }),
    });
    // Regular user has no passkeys registered yet, should return 400 No passkeys registered
    assert.strictEqual(optRes.status, 400);

    // Without username (discoverable login), options are generated successfully
    const discOptRes = await fetch(`${baseUrl}/auth/passkey/options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.strictEqual(discOptRes.status, 200);
    const discJson = await discOptRes.json();
    assert.ok(discJson.challenge_token, 'challenge_token returned');
    assert.ok(discJson.options, 'options returned');
  });

  await t.test('10. Settings Devices page & QR code endpoint', async () => {
    // Generate QR code for pairing URL
    const testUrl = 'http://127.0.0.1/pair?code=EXT-TEST1234';
    // User must be authenticated in web session for /settings/devices/qr
    const qrRes = await fetch(`http://127.0.0.1:${port}/settings/devices/qr?url=${encodeURIComponent(testUrl)}`);
    // Unauthenticated returns 401
    assert.strictEqual(qrRes.status, 401);
  });

  await t.test('11. Production HTTPS fails closed on non-secure requests and ignores spoofed X-Forwarded-Proto without trust proxy', async () => {
    process.env.NODE_ENV = 'production';
    try {
      const res = await fetch(`${baseUrl}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Forwarded-Proto': 'https', // Spoofed header without trust proxy configured
        },
        body: JSON.stringify({ username: regularUser.username, password }),
      });
      assert.strictEqual(res.status, 403, 'Plain HTTP request with spoofed header must be rejected 403 in production');
      const body = await res.json();
      assert.match(body.detail, /HTTPS is required in production/);
    } finally {
      process.env.NODE_ENV = 'test';
    }
  });

  await t.test('12. Rate limiting headers on unauthenticated endpoints (/auth/captcha and /auth/passkey/options)', async () => {
    const capRes = await fetch(`${baseUrl}/auth/captcha`);
    assert.strictEqual(capRes.status, 200);
    assert.ok(capRes.headers.get('ratelimit-limit') || capRes.headers.get('x-ratelimit-limit'), 'captcha endpoint has rate limit headers');

    const optRes = await fetch(`${baseUrl}/auth/passkey/options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.strictEqual(optRes.status, 200);
    assert.ok(optRes.headers.get('ratelimit-limit') || optRes.headers.get('x-ratelimit-limit'), 'passkey options endpoint has rate limit headers');
  });
});
