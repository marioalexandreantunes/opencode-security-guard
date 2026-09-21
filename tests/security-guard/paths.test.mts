// Table-driven tests pinning the SENSITIVE_PATHS catalogue and the disk scan
// (strengthen-paths-mutation-tests). Hermetic: deletes the extra-paths variable
// before import so the catalogue is exactly the built-in list.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/paths.test.mts
import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, rmSync, truncateSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

delete process.env.SECURITY_GUARD_EXTRA_PATHS

const cfg = await import("../../src/config.ts")
const { SENSITIVE_PATHS, isSensitivePath, isSensitivePathFor, escapeRe, diskHasSecrets, DISK_SCAN_MAX_BYTES } =
    await import("../../src/paths.ts")

// A deterministic AWS-shaped key (regex `\bAKIA[0-9A-Z]{16}\b`); split so the
// source text never contains a full literal secret.
const SECRET = "AKIA" + "A1B2C3D4E5F6G7H8"

type Case = { name: string; positives: string[]; negatives: string[] }

// One row per SENSITIVE_PATHS entry, in catalogue order. Positives/negatives are
// written against `/` (the patterns are normalised paths). Rows carry enough
// cases to exercise every alternation branch and quantifier/character-class site
// of their pattern, not just one positive. Reordering the catalogue requires
// reordering these rows — the size assertion below turns that into a red test.
const CASES: Case[] = [
    {
        name: ".env",
        positives: [".env", ".env.local", ".envrc", "proj/.env", ".ENV"],
        negatives: ["notes.env", "x.env", "proj/.env/foo", ".environment", ".envrc2"],
    },
    {
        name: "id_(rsa|ed25519|ecdsa|dsa)",
        positives: ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "id_rsa.pub", "home/id_ed25519.pub"],
        negatives: ["id_rsa.pem.bak", "id_rsa.pub.bak", "myid_rsa", "id_rsa2"],
    },
    {
        name: "key/cert extensions",
        positives: [
            "cert.pem",
            "server.key",
            "bundle.pfx",
            "cert.p12",
            "store.jks",
            "key.asc",
            "key.ppk",
            "dir/notes.PEM",
        ],
        negatives: ["notes.pem.bak", "keychain/notes", "cert.pem.bak"],
    },
    {
        name: ".ssh/",
        positives: [".ssh/config", "home/.ssh/id_rsa", ".ssh/"],
        negatives: [".ssh-config", ".sshfoo/x", "notes.ssh"],
    },
    {
        name: ".gnupg/",
        positives: [".gnupg/trustdb.gpg", "home/.gnupg/"],
        negatives: [".gnupg-config", ".gnupgfoo/x"],
    },
    {
        name: ".aws/(credentials|config)",
        positives: [".aws/credentials", ".aws/config", "home/.aws/credentials", ".AWS/credentials"],
        negatives: [".aws/hello.json", ".aws/credentials.bak"],
    },
    {
        name: ".kube/config",
        positives: [".kube/config", "home/.kube/config"],
        negatives: [".kube/config.yaml", ".kube/configs"],
    },
    {
        name: "dotfile credentials",
        positives: [".npmrc", ".netrc", ".pgpass", ".git-credentials", ".htpasswd", "home/.npmrc"],
        negatives: [".npmrc.bak", "my.npmrc", ".npmrcx"],
    },
    {
        name: ".docker/config.json",
        positives: [".docker/config.json", "home/.docker/config.json"],
        negatives: [".docker/config.yaml", ".docker/config.json.bak"],
    },
    {
        name: "credentials(.json)?",
        positives: ["credentials", "credentials.json", "home/credentials", "aws/credentials.json"],
        negatives: ["mycredentials", "credentials.bak", "credentials.json.bak"],
    },
    {
        name: "secrets?.(yaml|yml)",
        positives: ["secret.yml", "secrets.yaml", "config/secrets.yml", "secret.yaml", "config/secrets.YAML"],
        negatives: ["secrets.yaml.bak", "mysecrets.yml", "secrets.ymlx"],
    },
    {
        name: "shadow|wallet.dat",
        positives: ["shadow", "/etc/shadow", "wallet.dat", "a/wallet.dat"],
        negatives: ["shadow.bak", "myshadow", "wallet.dat.bak"],
    },
    {
        name: "keystore",
        positives: [
            "keystore.jks",
            "xkeystore.jks",
            "keystorex.jks",
            "a/b/keystore.jks",
            "my-keystore.p12",
            "keystore.bks",
        ],
        negatives: ["keystore-lib/src/main.rs", "cargo test -p keystore-lib", "keystore.jks.bak"],
    },
    {
        name: "license.lic",
        positives: ["license.lic", "dir/license.lic", "LICENSE.LIC"],
        negatives: ["license.txt", "license.lic.bak", "mylicense.lic"],
    },
    {
        name: ".security-guard/",
        positives: [".security-guard/", "proj/.security-guard/blacklist", ".security-guard/log"],
        negatives: [".security-guardx/log", "security-guard/x", ".security-guard"],
    },
]

test("catalogue: the table matches SENSITIVE_PATHS size and order", () => {
    assert.equal(SENSITIVE_PATHS.length, 15, "extra paths leaked into the catalogue")
    assert.equal(CASES.length, SENSITIVE_PATHS.length, "a pattern has no case row (or vice versa)")
})

test("catalogue: every pattern matches its positives and rejects its negatives", () => {
    for (let i = 0; i < CASES.length; i++) {
        const { name, positives, negatives } = CASES[i]
        const re = SENSITIVE_PATHS[i]
        for (const p of positives) {
            const n = cfg.norm(p)
            assert.ok(re.test(n), `${name}: expected to match ${p}`)
            assert.equal(isSensitivePath(p), true, `${name}: isSensitivePath rejected positive ${p}`)
        }
        for (const x of negatives) {
            const n = cfg.norm(x)
            assert.ok(!re.test(n), `${name}: expected NOT to match ${x}`)
            assert.equal(isSensitivePath(x), false, `${name}: isSensitivePath accepted negative ${x}`)
        }
    }
})

test("catalogue: no negative matches any other pattern", () => {
    for (const { name, negatives } of CASES) {
        for (const x of negatives) {
            assert.equal(isSensitivePath(x), false, `${name}: negative ${x} overlaps another pattern`)
        }
    }
})

test("cross-platform: drive letters, UNC, separators and case", () => {
    const sensitive = [
        "C:\\Users\\me\\.env",
        "\\\\server\\share\\.env",
        "D:/work/.aws/credentials",
        "c:\\proj\\.ENV",
        "C:\\Users\\me\\.ssh\\config",
    ]
    for (const p of sensitive) assert.equal(isSensitivePath(p), true, p)
    assert.equal(isSensitivePath("C:\\proj\\notes.txt"), false, "ordinary file")
    assert.equal(isSensitivePath("keystore-lib"), false, "a repository name is not a keystore file")
    assert.equal(isSensitivePath("cargo test -p keystore-lib"), false, "a cargo flag is not a keystore file")
})

test("escapeRe escapes regex metacharacters", () => {
    const raw = "a.b+c(d)[e]$^|{f}\\g"
    assert.ok(new RegExp(escapeRe(raw)).test(raw), "escaped pattern must match literally")
    assert.equal(new RegExp(escapeRe("x$y")).test("xy"), false, "$ must be escaped")
    assert.equal(escapeRe("."), "\\.")
})

test("diskHasSecrets: scanned vs skipped boundaries", () => {
    const dir = mkdtempSync(join(tmpdir(), "sg-disk-"))
    try {
        assert.equal(diskHasSecrets(join(dir, "missing.txt")), false, "missing path")

        const sub = join(dir, "sub")
        mkdirSync(sub)
        assert.equal(diskHasSecrets(sub), false, "directory is not a file")

        const clean = join(dir, "clean.txt")
        writeFileSync(clean, "an ordinary note, no secret here\n", "utf8")
        assert.equal(diskHasSecrets(clean), false, "scanned file with no hit")

        const secret = join(dir, "secret.txt")
        writeFileSync(secret, `${SECRET}\n`, "utf8")
        assert.equal(diskHasSecrets(secret), true, "secret-bearing file")

        const atMax = join(dir, "at-max.txt")
        writeFileSync(atMax, `${SECRET}\n`, "utf8")
        truncateSync(atMax, DISK_SCAN_MAX_BYTES)
        assert.equal(diskHasSecrets(atMax), true, "exactly DISK_SCAN_MAX_BYTES is scanned")

        const overMax = join(dir, "over-max.txt")
        writeFileSync(overMax, `${SECRET}\n`, "utf8")
        truncateSync(overMax, DISK_SCAN_MAX_BYTES + 1)
        assert.equal(diskHasSecrets(overMax), false, "over DISK_SCAN_MAX_BYTES is skipped")
    } finally {
        rmSync(dir, { recursive: true, force: true })
    }
})

// Run last: this relocates the process-wide LOG_FILE, which the tests above
// must not depend on.
test("guard log: active log and its .1 rotation are sensitive (case-insensitive)", () => {
    const dir = mkdtempSync(join(tmpdir(), "sg-log-"))
    const log = join(dir, "guard.log")
    const previous = cfg.LOG_FILE
    try {
        cfg.setLogFile(log)
        assert.equal(cfg.LOG_FILE, log)
        assert.equal(isSensitivePath(log), true, "active log")
        assert.equal(isSensitivePath(`${log}.1`), true, "rotation")
        assert.equal(isSensitivePath(log.toUpperCase()), true, "case-insensitive")
        assert.equal(isSensitivePath(previous), false, "the previous log is no longer special")
    } finally {
        cfg.setLogFile(previous)
        rmSync(dir, { recursive: true, force: true })
    }
})

// ── Windows path regressions (fix-windows-test-suite) ─────────────────────
// `norm()` folds `\` to `/`; expectations are written against the normalized
// form so the same assertion holds on every platform.
test("norm: Windows separators fold to forward slashes", () => {
    assert.equal(cfg.norm("C:\\proj\\notes.txt"), "C:/proj/notes.txt")
    assert.equal(cfg.norm("C:\\proj\\sub\\.env"), "C:/proj/sub/.env")
    assert.equal(cfg.norm("C:/proj\\mixed/x.txt"), "C:/proj/mixed/x.txt")
    assert.equal(cfg.norm("relative\\dir\\file.txt"), "relative/dir/file.txt")
})

test("sensitive paths: Windows drive, mixed separators and case are detected", () => {
    const sensitive = [
        "C:\\proj\\.env",
        "C:/proj/.env",
        "C:/proj\\.env",
        "C:\\PROJ\\.ENV",
        "D:\\work\\config\\.aws\\credentials",
        "C:\\Users\\me\\.ssh\\id_rsa",
        "\\\\server\\share\\.env",
    ]
    for (const p of sensitive) assert.equal(isSensitivePath(p), true, p)
    const ordinary = ["C:\\proj\\notes.txt", "C:\\proj\\src\\index.ts", "notes.txt", "plain.txt"]
    for (const p of ordinary) assert.equal(isSensitivePath(p), false, p)
})

test("logPathFor: a Windows drive path stays lexical on a POSIX base", () => {
    // On POSIX a drive path is not absolute, so it passes through normalized.
    assert.equal(cfg.logPathFor("/base", "C:\\proj\\.env"), "C:/proj/.env")
    assert.equal(cfg.logPathFor("/base", "relative\\x.txt"), "relative/x.txt")
})

test("isSensitivePathFor: a real root keeps ordinary relative names allowed", () => {
    const dir = mkdtempSync(join(tmpdir(), "sg-scope-"))
    try {
        const scope = { logFile: join(dir, "guard.log"), root: dir }
        assert.equal(isSensitivePathFor(scope, "notes.txt"), false, "an ordinary relative name is not sensitive")
        assert.equal(
            isSensitivePathFor(scope, join(dir, "notes.txt")),
            false,
            "an ordinary in-root file is not sensitive",
        )
        assert.equal(isSensitivePathFor(scope, ".env"), true, "a sensitive name stays sensitive")
        assert.equal(isSensitivePathFor(scope, join(dir, ".env")), true, "a sensitive in-root target stays sensitive")
    } finally {
        rmSync(dir, { recursive: true, force: true })
    }
})
