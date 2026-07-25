// main.go — Trigger file for the zero-click exploit chain
//
// This file is the auto-opened target in the Cloud Shell deep link:
//   ?cloudshell_git_repo=<url>&cloudshell_open_in_editor=main.go
//
// When Cloud Shell opens this file:
//   1. The Go extension (pre-installed in Cloud Shell) activates
//   2. It reads .vscode/settings.json → sees "go.alternateTools"
//   3. It spawns ./gopls-wrapper as the Go language server
//   4. lsp-server.js takes over → __proto__ pollution → XSS
//
// The file is intentionally minimal to avoid suspicion.

package main

import "fmt"

func main() {
	fmt.Println("Hello, Cloud Shell!")
}
