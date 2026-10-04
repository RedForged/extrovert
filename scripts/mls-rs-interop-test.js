'use strict';

/**
 * Cross-Implementation Interoperability Harness (TASK-1A-2)
 *
 * Verifies RFC 9420 wireformat and semantic cryptographic interoperability
 * between two independent implementations:
 * 1. ts-mls (v1.6.4, TypeScript / @noble) - Client Alice
 * 2. mls-rs (v0.56.0, Rust / RustCrypto)  - Client Bob
 *
 * Flow:
 * - Bob (mls-rs) generates RFC 9420 KeyPackage
 * - Alice (ts-mls) ingests Bob's KeyPackage, creates group, adds Bob, commits (ratchet tree ext), generates Welcome
 * - Alice (ts-mls) encrypts an ApplicationMessage
 * - Bob (mls-rs) processes Welcome, joins group at epoch 1
 * - Bob (mls-rs) decrypts Alice's ApplicationMessage -> matches plaintext
 * - Bob (mls-rs) encrypts an ApplicationMessage reply
 * - Alice (ts-mls) decrypts Bob's ApplicationMessage reply -> matches plaintext
 */

const assert = require('assert');
const { spawn } = require('child_process');
const path = require('path');
const readline = require('readline');

// Setup WebCrypto shim for Node.js
global.window = global;
if (!global.crypto) {
  global.crypto = require('crypto').webcrypto;
}
require('../public/lib/mls.js');
const mls = window.MLS;

class MlsRsBridge {
  constructor(binaryPath) {
    this.proc = spawn(binaryPath, [], {
      stdio: ['pipe', 'pipe', 'inherit'],
    });
    this.rl = readline.createInterface({ input: this.proc.stdout });
    this.pendingResolves = [];

    this.rl.on('line', (line) => {
      const resolver = this.pendingResolves.shift();
      if (resolver) {
        try {
          const json = JSON.parse(line.trim());
          resolver(json);
        } catch (err) {
          resolver({ status: 'error', message: err.message });
        }
      }
    });
  }

  async send(cmd) {
    return new Promise((resolve) => {
      this.pendingResolves.push(resolve);
      this.proc.stdin.write(JSON.stringify(cmd) + '\n');
    });
  }

  close() {
    this.proc.stdin.end();
    this.proc.kill();
  }
}

async function run() {
  console.log('=== Starting RFC 9420 Cross-Implementation Interoperability Suite (TASK-1A-2) ===\n');
  console.log('Implementations under test:');
  console.log('  - Implementation A: ts-mls @ 1.6.4 (TypeScript, @noble/curves, @noble/ciphers)');
  console.log('  - Implementation B: mls-rs @ 0.56.0 (Rust, mls-rs-crypto-rustcrypto, ed25519-dalek, x25519-dalek)\n');

  const rustBin = path.join(__dirname, 'interop-mls-rs', 'target', 'debug', 'mls-rs-interop');
  const bob = new MlsRsBridge(rustBin);

  try {
    // 1. Initialize Bob (mls-rs) and export KeyPackage
    console.log('1. Generating Bob (mls-rs) RFC 9420 KeyPackage...');
    const initRes = await bob.send({ action: 'init', identity: 'bob_mls_rs' });
    assert.strictEqual(initRes.status, 'ok', `Bob init failed: ${initRes.message}`);
    assert.ok(initRes.key_package_hex, 'Bob must return key_package_hex');
    console.log(`   [OK] Bob generated KeyPackage: ${initRes.key_package_hex.length / 2} bytes\n`);

    // 2. Alice (ts-mls) initializes ciphersuite
    console.log('2. Alice (ts-mls) initializing ciphersuite MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519...');
    const cs = mls.getCiphersuiteFromName('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519');
    const impl = await mls.getCiphersuiteImpl(cs);
    assert.ok(impl, 'Ciphersuite must be loaded');

    const aliceCred = {
      credentialType: 'basic',
      identity: new TextEncoder().encode('alice_ts_mls'),
    };
    const aliceKp = await mls.generateKeyPackage(aliceCred, mls.defaultCapabilities(), mls.defaultLifetime, [], impl);
    console.log('   [OK] Alice initialized\n');

    // 3. Alice decodes Bob's KeyPackage
    console.log("3. Alice (ts-mls) parsing Bob's (mls-rs) KeyPackage wireformat bytes...");
    const bobKpBytes = new Uint8Array(Buffer.from(initRes.key_package_hex, 'hex'));
    const [bobDecodedKp] = mls.decodeMlsMessage(bobKpBytes, 0);
    assert.strictEqual(bobDecodedKp.wireformat, 'mls_key_package', 'Wireformat must be mls_key_package');
    assert.strictEqual(bobDecodedKp.version, 'mls10', 'Version must be mls10');
    console.log('   [OK] Alice successfully deserialized Bob’s KeyPackage\n');

    // 4. Alice creates group and commits AddProposal(Bob)
    console.log('4. Alice creating MLS group and committing AddProposal for Bob...');
    const groupId = new TextEncoder().encode('interop_tsmls_mlsrs_dm');
    let aliceGroup = await mls.createGroup(groupId, aliceKp.publicPackage, aliceKp.privatePackage, [], impl);
    assert.strictEqual(aliceGroup.groupContext.epoch, 0n);

    const addBobProposal = {
      proposalType: 'add',
      add: { keyPackage: bobDecodedKp.keyPackage },
    };

    const commitRes = await mls.createCommit(
      { state: aliceGroup, cipherSuite: impl },
      { extraProposals: [addBobProposal], ratchetTreeExtension: true }
    );
    aliceGroup = commitRes.newState;
    commitRes.consumed.forEach(mls.zeroOutUint8Array);

    assert.strictEqual(aliceGroup.groupContext.epoch, 1n, 'Alice advanced to epoch 1');
    assert.ok(commitRes.welcome, 'Welcome message must be generated');

    const welcomeBytes = mls.encodeMlsMessage({
      welcome: commitRes.welcome,
      wireformat: 'mls_welcome',
      version: 'mls10',
    });
    console.log(`   [OK] Group created. Welcome generated: ${welcomeBytes.length} bytes\n`);

    // 5. Alice encrypts an ApplicationMessage
    console.log('5. Alice (ts-mls) encrypting an ApplicationMessage for the group...');
    const alicePlaintext = 'Hello Bob! This is an MLS RFC 9420 application message created by ts-mls.';
    const appMsgRes = await mls.createApplicationMessage(
      aliceGroup,
      new TextEncoder().encode(alicePlaintext),
      impl
    );
    aliceGroup = appMsgRes.newState;
    appMsgRes.consumed.forEach(mls.zeroOutUint8Array);

    const appMsgBytes = mls.encodeMlsMessage({
      privateMessage: appMsgRes.privateMessage,
      wireformat: 'mls_private_message',
      version: 'mls10',
    });
    console.log(`   [OK] Alice encrypted message: ${appMsgBytes.length} bytes\n`);

    // 6. Bob (mls-rs) joins group via Welcome
    console.log('6. Bob (mls-rs) processing Welcome message from Alice (ts-mls)...');
    const joinRes = await bob.send({
      action: 'join_group',
      welcome_hex: Buffer.from(welcomeBytes).toString('hex'),
    });
    assert.strictEqual(joinRes.status, 'ok', `Bob join_group failed: ${joinRes.message}`);
    assert.strictEqual(joinRes.epoch, 1, 'Bob epoch must be 1');
    console.log('   [OK] Bob successfully joined group at epoch 1\n');

    // 7. Bob (mls-rs) decrypts Alice's ApplicationMessage
    console.log("7. Bob (mls-rs) decrypting Alice's (ts-mls) ApplicationMessage...");
    const decryptRes = await bob.send({
      action: 'decrypt_message',
      ciphertext_hex: Buffer.from(appMsgBytes).toString('hex'),
    });
    assert.strictEqual(decryptRes.status, 'ok', `Bob decrypt failed: ${decryptRes.message}`);
    assert.strictEqual(decryptRes.plaintext, alicePlaintext, 'Plaintext must match exactly');
    console.log(`   [OK] Bob successfully decrypted message:\n       "${decryptRes.plaintext}"\n`);

    // 8. Bob (mls-rs) encrypts a reply ApplicationMessage
    console.log('8. Bob (mls-rs) encrypting a reply ApplicationMessage for Alice (ts-mls)...');
    const bobPlaintext = 'Greetings Alice! This reply was encrypted by mls-rs in Rust.';
    const encryptRes = await bob.send({
      action: 'encrypt_message',
      plaintext: bobPlaintext,
    });
    assert.strictEqual(encryptRes.status, 'ok', `Bob encrypt failed: ${encryptRes.message}`);
    assert.ok(encryptRes.ciphertext_hex, 'Bob must return ciphertext_hex');
    console.log(`   [OK] Bob encrypted reply: ${encryptRes.ciphertext_hex.length / 2} bytes\n`);

    // 9. Alice (ts-mls) decrypts Bob's ApplicationMessage
    console.log("9. Alice (ts-mls) decrypting Bob's (mls-rs) reply ApplicationMessage...");
    const bobCtBytes = new Uint8Array(Buffer.from(encryptRes.ciphertext_hex, 'hex'));
    const [bobDecodedAppMsg] = mls.decodeMlsMessage(bobCtBytes, 0);
    assert.strictEqual(bobDecodedAppMsg.wireformat, 'mls_private_message', 'Wireformat must be mls_private_message');

    const aliceDecrypted = await mls.processPrivateMessage(
      aliceGroup,
      bobDecodedAppMsg.privateMessage,
      mls.emptyPskIndex,
      impl
    );
    aliceGroup = aliceDecrypted.newState;
    const alicePlaintextReceived = new TextDecoder().decode(aliceDecrypted.message);

    assert.strictEqual(alicePlaintextReceived, bobPlaintext, 'Alice must decrypt Bob’s exact plaintext');
    console.log(`   [OK] Alice successfully decrypted Bob’s reply:\n       "${alicePlaintextReceived}"\n`);

    console.log('=== Cross-Implementation Interoperability (TASK-1A-2) PASSED 100%! ===');
    console.log('Summary:');
    console.log('  - KeyPackage exchange: mls-rs -> ts-mls (VALIDATED)');
    console.log('  - Group creation & Welcome: ts-mls -> mls-rs (VALIDATED)');
    console.log('  - Forward encryption: ts-mls -> mls-rs (VALIDATED)');
    console.log('  - Backward encryption: mls-rs -> ts-mls (VALIDATED)');
    console.log('  - Ratchet tree sync: Validated across epoch 1\n');
  } finally {
    bob.close();
  }
}

run().catch((err) => {
  console.error('\nInteroperability test failed:', err);
  process.exit(1);
});
