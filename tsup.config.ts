import { defineConfig } from "tsup"

export default defineConfig({
    entry: { "security-guard": "src/index.ts" },
    format: ["esm"],
    target: "node22",
    dts: true,
    outDir: "dist",
    clean: true,
    sourcemap: false,
    splitting: false,
})
