/**
 * write-policy.ts — write-destination policy for write/edit/patch operations.
 * Lexical helpers stay for compatibility; the canonical boundary resolver
 * follows links (symlinks/junctions) through the nearest existing ancestor so
 * a lexically in-root destination cannot escape the worktree unseen.
 */
import * as fsx from "node:fs"
import * as p from "node:path"

/** Project root for the rehydration destination policy. */
export function resolveProjectRoot(worktree: unknown, directory: unknown): string {
    const worktreePath = typeof worktree === "string" && worktree.trim() !== "" ? p.resolve(worktree) : null
    const directoryPath = typeof directory === "string" && directory.trim() !== "" ? p.resolve(directory) : null

    // OpenCode uses the filesystem root as worktree for global, non-Git projects.
    if (worktreePath !== null) {
        const isRoot = worktreePath === p.parse(worktreePath).root
        const directoryIsConcrete = directoryPath !== null && directoryPath !== p.parse(directoryPath).root
        if (isRoot && directoryIsConcrete) return directoryPath
        return worktreePath
    }
    if (directoryPath !== null) return directoryPath
    return p.resolve(process.cwd())
}

/** True when `target` resolves inside `root` (fail-closed on `..`). */
export function isInsideWorktree(root: string, target: string): boolean {
    if (!target) return true
    const rel = p.relative(root, p.resolve(root, target))
    return rel === "" || (!rel.startsWith("..") && !p.isAbsolute(rel))
}

/** Every destination a write/edit/patch operation may touch. */
export function writeTargets(args: unknown): string[] {
    const record = (args ?? {}) as Record<string, unknown>
    const targets: string[] = [record.filePath, record.path].filter(
        (v): v is string => typeof v === "string" && v.length > 0,
    )
    for (const line of String(record.patchText ?? "").split("\n")) {
        const match = line.match(/^\*\*\* (?:Add File|Update File|Move to|Delete File):\s*(.+)$/)
        const target = match?.[1]
        if (target !== undefined) targets.push(target.trim())
    }
    return targets
}

/** Canonical boundary verdict for one destination. */
export type DestinationVerdict = "inside" | "outside" | "unverifiable"

/** One destination compared against the canonical project root. */
export interface ClassifiedDestination {
    readonly verdict: DestinationVerdict
    /** Canonical root, or `null` when it cannot be inspected. */
    readonly canonicalRoot: string | null
    /** Canonical target (nearest existing ancestor plus missing suffix), or `null`. */
    readonly canonicalTarget: string | null
}

/** Platform-native realpath: follows symlinks and Windows junctions. */
function realpathNative(path: string): string {
    const native = (fsx.realpathSync as typeof fsx.realpathSync & { native?: (path: string) => string }).native
    return native ? native(path) : fsx.realpathSync(path)
}

/** Canonical root, or `null` when it cannot be inspected (fail closed). */
export function canonicalizeRoot(root: string): string | null {
    try {
        return realpathNative(p.resolve(root))
    } catch {
        return null
    }
}

/**
 * Canonical target: realpath of the existing target, else the nearest existing
 * ancestor plus the missing suffix. `null` when nothing up the chain inspects.
 */
export function resolveCanonicalTarget(root: string, target: string): string | null {
    const missing: string[] = []
    let current = p.resolve(root, target)
    for (;;) {
        try {
            const resolved = realpathNative(current)
            return missing.length ? p.join(resolved, ...missing.reverse()) : resolved
        } catch {
            const parent = p.dirname(current)
            if (parent === current) return null
            missing.push(p.basename(current))
            current = parent
        }
    }
}

/** Path-boundary-aware containment of a canonical target in a canonical root. */
function containsBoundary(canonicalRoot: string, canonicalTarget: string): boolean {
    const rel = p.relative(canonicalRoot, canonicalTarget)
    return rel === "" || (!rel.startsWith("..") && !p.isAbsolute(rel))
}

/**
 * Classifies one destination against the canonical project root. Link escapes
 * (existing symlinks, junctions, linked parents) resolve outside; a missing
 * root or ancestor is `unverifiable` so callers fail closed.
 */
export function classifyDestination(
    root: string,
    target: string,
    /**
     * Already-resolved canonical root (the factory resolves it once); when
     * omitted the root is canonicalized here. Passing it avoids re-resolving
     * the same root for every destination of a hook call.
     */
    canonicalRootOverride?: string | null,
): ClassifiedDestination {
    if (!target) return { verdict: "inside", canonicalRoot: null, canonicalTarget: null }
    const canonicalRoot = canonicalRootOverride ?? canonicalizeRoot(root)
    if (canonicalRoot === null) return { verdict: "unverifiable", canonicalRoot, canonicalTarget: null }
    const canonicalTarget = resolveCanonicalTarget(root, target)
    if (canonicalTarget === null) {
        return { verdict: "unverifiable", canonicalRoot, canonicalTarget }
    }
    return {
        verdict: containsBoundary(canonicalRoot, canonicalTarget) ? "inside" : "outside",
        canonicalRoot,
        canonicalTarget,
    }
}
