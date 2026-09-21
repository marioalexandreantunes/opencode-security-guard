/**
 * vault.ts — in-memory marker-hash -> secret value vault with LRU eviction.
 * No internal dependencies and no disk persistence: secrets live only in memory.
 */

const DEFAULT_MAX = 1000

/** Reads `SECURITY_GUARD_VAULT_MAX`; falls back to `DEFAULT_MAX` if unset/invalid. */
function configuredMax(): number {
    const n = Number(process.env.SECURITY_GUARD_VAULT_MAX ?? DEFAULT_MAX)
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_MAX
}

export interface Vault {
    /** Store/refresh a value under its marker hash (LRU order). */
    store(hash: string, value: string): void
    /** Look up a value by marker hash (refreshes LRU order). */
    lookup(hash: string): string | undefined
    /** Drop every entry. */
    clear(): void
    readonly size: number
}

export function createVault(max: number = configuredMax()): Vault {
    // Map preserves insertion order; delete+set implements LRU.
    const valueByHash = new Map<string, string>()

    function store(hash: string, value: string): void {
        if (valueByHash.has(hash)) valueByHash.delete(hash)
        valueByHash.set(hash, value)
        while (valueByHash.size > max) {
            const oldest = valueByHash.keys().next().value
            if (oldest === undefined) break
            valueByHash.delete(oldest)
        }
    }

    function lookup(hash: string): string | undefined {
        const value = valueByHash.get(hash)
        if (value !== undefined) {
            valueByHash.delete(hash)
            valueByHash.set(hash, value)
        }
        return value
    }

    function clear(): void {
        valueByHash.clear()
    }

    return {
        store,
        lookup,
        clear,
        get size() {
            return valueByHash.size
        },
    }
}
