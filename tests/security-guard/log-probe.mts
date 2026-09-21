// D7 test-only probe seam: the production event registry (`LogPayload`) is
// closed, but tests legitimately emit ad-hoc probe event names to observe the
// writer (rotation, relocation, failure paths). This helper performs the one
// documented cast from an ad-hoc probe name to the `writeLog` boundary.
// Production code MUST NOT import it; the cast is recorded in the owning
// OpenSpec change's evidence.md.
import type { LogLevel, LogPayload } from "../../src/config.ts"

type WriteLog = <E extends keyof LogPayload>(level: LogLevel, event: E, data?: LogPayload[E]) => void

export const logProbe = (
    writeLog: WriteLog,
): ((level: LogLevel, event: string, data?: Record<string, unknown>) => void) =>
    // The single deliberate cast in the suite: probe names stay outside the
    // production registry by design.
    writeLog as unknown as (level: LogLevel, event: string, data?: Record<string, unknown>) => void
