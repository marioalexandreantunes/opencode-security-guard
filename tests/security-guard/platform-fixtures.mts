/**
 * platform-fixtures.mts — portable link fixtures for the canonical-boundary
 * suites (fix-windows-test-suite).
 *
 * Windows requires Developer Mode or elevation to create a *file* symlink, but
 * directory junctions need no privilege. So directory-link scenarios use a
 * junction on Windows and a symlink elsewhere, while file-link scenarios probe
 * the capability once and report a narrow `PLATFORM-LIMITATION` when the host
 * denies it. Fixtures are created lazily by each suite, never at import time,
 * so a denied privilege can never fail a whole module at load.
 */
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"

/** Stable reason prefix used by privilege-dependent skips. */
export const PLATFORM_LIMITATION = "PLATFORM-LIMITATION"

let fileLinkCapability: boolean | null = null

const isWindowsLinkPermissionError = (error: unknown): boolean => {
    if (process.platform !== "win32" || typeof error !== "object" || error === null) return false
    const code = (error as NodeJS.ErrnoException).code
    return code === "EACCES" || code === "EPERM"
}

/**
 * Probes, once, whether this process may create a file symlink. Uses a private
 * temporary fixture and always cleans it up. Only Windows permission errors
 * become a negative capability result; unrelated failures are propagated.
 */
export function canLinkFiles(): boolean {
    if (fileLinkCapability !== null) return fileLinkCapability
    const dir = mkdtempSync(join(tmpdir(), "sg-link-probe-"))
    try {
        const target = join(dir, "target.txt")
        writeFileSync(target, "probe\n")
        try {
            symlinkSync(target, join(dir, "link.txt"), "file")
            fileLinkCapability = true
        } catch (error) {
            if (!isWindowsLinkPermissionError(error)) throw error
            fileLinkCapability = false
        }
    } finally {
        rmSync(dir, { recursive: true, force: true })
    }
    return fileLinkCapability ?? false
}

/** Returns the only supported skip reason for file-link scenarios. */
export function fileLinkSkipReason(): string | undefined {
    if (process.platform !== "win32" || canLinkFiles()) return undefined
    return `${PLATFORM_LIMITATION}: file symlinks are unavailable on this host`
}

/**
 * Creates a directory link. Windows uses a junction because it does not
 * require file-symlink privileges; other platforms use a directory symlink.
 */
export function linkDir(target: string, linkPath: string): void {
    const type = process.platform === "win32" ? "junction" : "dir"
    symlinkSync(resolve(target), linkPath, type)
}

/** Creates a file symlink. Throws (EPERM on unprivileged Windows) when denied. */
export function linkFile(target: string, linkPath: string): void {
    symlinkSync(resolve(target), linkPath, "file")
}
