// security-guard regression harness.
// Imports the REAL internals from the modules (no string manipulation), to
// run the tests against the source code actually used.

import {
    API_WRITE,
    ENV_DUMP,
    ENV_ECHO,
    ENV_EXPORT,
    MARKER_RE,
    PS_ENV,
    sensitiveToken,
    WRITE_VERB,
} from "../../src/bash.ts"
import { fp, MARKER, norm } from "../../src/config.ts"
import { SecurityGuard } from "../../src/index.ts"
import { inspectDiskTarget, isSensitivePath, SENSITIVE_PATHS } from "../../src/paths.ts"
import { FAILED_PLACEHOLDER, redactDeep, redactSkipping, redactStrings } from "../../src/redact.ts"
import {
    CODEISH,
    createScanCache,
    entropy,
    INDICATOR,
    looksBare,
    looksReal,
    looksSecret,
    PATHISH,
    PLACEHOLDER,
    RULES,
    SCAN_CACHE_MAX,
    SHORTISH,
    scan,
    scanDeep,
    VERSIONISH,
    WORDISH,
} from "../../src/rules.ts"

export async function loadGuard(): Promise<Record<string, any>> {
    return {
        scan,
        scanDeep,
        sensitiveToken,
        isSensitivePath,
        inspectDiskTarget,
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
