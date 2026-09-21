/**
 * index.ts — public entry point. Exactly ONE export (SecurityGuard):
 * `export const X` + `export default X` registered the plugin twice on
 * older opencode versions.
 */

export { SecurityGuard } from "./plugin.ts"
