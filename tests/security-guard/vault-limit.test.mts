// Vault limit tests: SECURITY_GUARD_VAULT_MAX is read per createVault() call
// (it is a default parameter, not an import-time read), so the environment can
// be set and restored in-process. Each test verifies the observable eviction
// boundary rather than the internal value.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/vault-limit.test.mts

import assert from "node:assert/strict"
import { test } from "node:test"
import { createVault, type Vault } from "../../src/vault.ts"

const DEFAULT_MAX = 1000

function withVaultMax(value: string | undefined, run: () => void): void {
    const previous = process.env.SECURITY_GUARD_VAULT_MAX
    if (value === undefined) delete process.env.SECURITY_GUARD_VAULT_MAX
    else process.env.SECURITY_GUARD_VAULT_MAX = value
    try {
        run()
    } finally {
        if (previous === undefined) delete process.env.SECURITY_GUARD_VAULT_MAX
        else process.env.SECURITY_GUARD_VAULT_MAX = previous
    }
}

function storeEntries(vault: Vault, count: number): void {
    for (let i = 0; i < count; i++) vault.store(`h${i}`, `v${i}`)
}

test("vault limit: unset defaults to 1000 entries", () => {
    withVaultMax(undefined, () => {
        const vault = createVault()
        storeEntries(vault, DEFAULT_MAX + 1)
        assert.equal(vault.size, DEFAULT_MAX)
        assert.equal(vault.lookup("h0"), undefined)
        assert.equal(vault.lookup(`h${DEFAULT_MAX}`), `v${DEFAULT_MAX}`)
    })
})

test("vault limit: invalid and non-positive values fall back to the default", () => {
    for (const value of ["abc", "", "0", "-5"]) {
        withVaultMax(value, () => {
            const vault = createVault()
            storeEntries(vault, DEFAULT_MAX + 1)
            assert.equal(vault.size, DEFAULT_MAX, `SECURITY_GUARD_VAULT_MAX=${JSON.stringify(value)}`)
        })
    }
})

test("vault limit: a valid positive value sets the limit", () => {
    withVaultMax("5", () => {
        const vault = createVault()
        storeEntries(vault, 6)
        assert.equal(vault.size, 5)
        assert.equal(vault.lookup("h0"), undefined)
        assert.equal(vault.lookup("h5"), "v5")
    })
})

test("vault limit: a fractional value is floored", () => {
    withVaultMax("2.5", () => {
        const vault = createVault()
        storeEntries(vault, 3)
        assert.equal(vault.size, 2)
        assert.equal(vault.lookup("h0"), undefined)
        assert.equal(vault.lookup("h2"), "v2")
    })
})

test("vault limit: an infinite value falls back to the default", () => {
    withVaultMax("Infinity", () => {
        const vault = createVault()
        storeEntries(vault, DEFAULT_MAX + 1)
        assert.equal(vault.size, DEFAULT_MAX)
    })
})
