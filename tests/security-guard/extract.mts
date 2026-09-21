// security-guard regression harness.
// Imports the REAL internals from the modules (no string manipulation), to
// run the tests against the source code actually used.
import { MARKER, norm, fp } from "../../src/config.ts"
import {
    scan,
    scanDeep,
    RULES,
    INDICATOR,
    entropy,
    looksReal,
    looksSecret,
    looksBare,
    PLACEHOLDER,
    PATHISH,
    CODEISH,
    WORDISH,
    VERSIONISH,
    SHORTISH,
    createScanCache,
    SCAN_CACHE_MAX,
} from "../../src/rules.ts"
import { isSensitivePath, diskHasSecrets, SENSITIVE_PATHS } from "../../src/paths.ts"
import {
    sensitiveToken,
    ENV_DUMP,
    PS_ENV,
    ENV_ECHO,
    ENV_EXPORT,
    WRITE_VERB,
    API_WRITE,
    MARKER_RE,
} from "../../src/bash.ts"
import { SecurityGuard } from "../../src/index.ts"
import { redactStrings, redactDeep, redactSkipping, FAILED_PLACEHOLDER } from "../../src/redact.ts"

export async function loadGuard(): Promise<Record<string, any>> {
    return {
        scan,
        scanDeep,
        sensitiveToken,
        isSensitivePath,
        diskHasSecrets,
        RULES,
        createScanCache,
        SCAN_CACHE_MAX,
        ENV_DUMP,
        PS_ENV,
        ENV_ECHO,
        ENV_EXPORT,
        WRITE_VERB,
        API_WRITE,
        MARKER_RE,
        MARKER,
        looksReal,
        looksSecret,
        looksBare,
        entropy,
        INDICATOR,
        SENSITIVE_PATHS,
        PLACEHOLDER,
        PATHISH,
        CODEISH,
        WORDISH,
        VERSIONISH,
        SHORTISH,
        norm,
        fp,
        redactStrings,
        redactDeep,
        redactSkipping,
        FAILED_PLACEHOLDER,
    }
}

/** Returns the real plugin factory (index.ts) for the smoke test. */
export async function loadFactory(): Promise<(input: any) => Promise<Record<string, any>>> {
    return SecurityGuard
}
