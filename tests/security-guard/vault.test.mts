// Vault unit tests.
import { test } from "node:test"
import assert from "node:assert/strict"
import { createVault } from "../../src/vault.ts"

test("vault: store and lookup", () => {
    const v = createVault(10)
    v.store("abc", "secret-1")
    assert.equal(v.lookup("abc"), "secret-1")
    assert.equal(v.lookup("nope"), undefined)
    assert.equal(v.size, 1)
})

test("vault: duplicate hash does not grow", () => {
    const v = createVault(10)
    v.store("abc", "secret-1")
    v.store("abc", "secret-1")
    assert.equal(v.size, 1)
})

test("vault: re-storing a hash refreshes its LRU position", () => {
    const v = createVault(2)
    v.store("a", "1")
    v.store("b", "2")
    v.store("a", "1") // refresh a -> b becomes the oldest
    v.store("c", "3") // evicts b
    assert.equal(v.lookup("b"), undefined)
    assert.equal(v.lookup("a"), "1")
    assert.equal(v.lookup("c"), "3")
    assert.equal(v.size, 2)
})

test("vault: LRU evicts the least recently used", () => {
    const v = createVault(2)
    v.store("a", "1")
    v.store("b", "2")
    v.lookup("a") // refresh a -> b becomes the oldest
    v.store("c", "3") // evicts b
    assert.equal(v.lookup("b"), undefined)
    assert.equal(v.lookup("a"), "1")
    assert.equal(v.lookup("c"), "3")
    assert.equal(v.size, 2)
})

test("vault: repeated stores past the limit keep only the most recent", () => {
    const v = createVault(2)
    for (const hash of ["a", "b", "c", "d", "e"]) v.store(hash, hash)
    assert.equal(v.size, 2)
    assert.equal(v.lookup("a"), undefined)
    assert.equal(v.lookup("b"), undefined)
    assert.equal(v.lookup("c"), undefined)
    assert.equal(v.lookup("d"), "d")
    assert.equal(v.lookup("e"), "e")
})

test("vault: a zero limit evicts immediately", () => {
    const v = createVault(0)
    v.store("a", "1")
    assert.equal(v.size, 0)
    assert.equal(v.lookup("a"), undefined)
})

test("vault: a negative limit empties through the guard path", () => {
    const v = createVault(-1)
    v.store("a", "1")
    assert.equal(v.size, 0)
    assert.equal(v.lookup("a"), undefined)
})

test("vault: a lookup miss leaves the vault unchanged", () => {
    const v = createVault(10)
    v.store("a", "1")
    assert.equal(v.lookup("nope"), undefined)
    assert.equal(v.size, 1)
    assert.equal(v.lookup("a"), "1")
})

test("vault: an undefined value is kept but never refreshes", () => {
    const v = createVault(10)
    v.store("x", undefined as unknown as string)
    assert.equal(v.size, 1)
    assert.equal(v.lookup("x"), undefined)
    v.store("x", "real")
    assert.equal(v.lookup("x"), "real")
})

test("vault: clear empties it", () => {
    const v = createVault(10)
    v.store("a", "1")
    v.clear()
    assert.equal(v.size, 0)
    assert.equal(v.lookup("a"), undefined)
})
