// property-p10-worker.mts — P-10 worker: runs scan() over adversarial inputs
// in an isolated process. A node:test timeout cannot interrupt a blocking
// synchronous regex, so the parent enforces a hard timeout on this process.
// Usage: node --experimental-strip-types property-p10-worker.mts <inputs.json>
import { readFileSync } from "node:fs"
import { scan } from "../../src/rules.ts"

const path = process.argv[2]
if (!path) {
    console.error("usage: property-p10-worker.mts <inputs.json>")
    process.exit(64)
}

const inputs = JSON.parse(readFileSync(path, "utf8")) as string[]
for (const input of inputs) {
    const start = Date.now()
    scan(input)
    const elapsed = Date.now() - start
    if (elapsed > 5000) {
        console.error(`SLOW INPUT (${elapsed}ms, ${input.length} chars)`)
        process.exit(2)
    }
}
console.log(`ok ${inputs.length} inputs`)
