/**
 * TRIGGER FILE — TSServer Zero-Click PoC
 * =======================================
 *
 * This file exists for one reason: to cause TSServer to initialize
 * and load its tsconfig.json plugin configuration.
 *
 * When this file is opened (via cloudshell_open_in_editor=main.ts),
 * TSServer auto-starts, walks up the directory tree to find
 * tsconfig.json, reads the "compilerOptions.plugins" array, and
 * require()s the plugin at the path traversal location.
 *
 * No user typing needed. No trust prompt needed.
 * TSServer loads plugins independently of workspace trust.
 */

const greeting: string = "Hello World";

interface User {
    name: string;
    email: string;
    role: "admin" | "user" | "viewer";
}

function processUser(user: User): string {
    return `User ${user.name} (${user.email}) has role: ${user.role}`;
}

const adminUser: User = {
    name: "Administrator",
    email: "admin@cloudshell.local",
    role: "admin",
};

console.log(greeting);
console.log(processUser(adminUser));

export { User, processUser };
