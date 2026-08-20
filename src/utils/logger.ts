/**
 * Lightweight debug logger for zero-auth.
 *
 * Logging is enabled when:
 * - `DEBUG=zero-auth` environment variable is set, OR
 * - `NODE_ENV=development` (only warnings and errors)
 *
 * In production, only errors are logged.
 */

type LogLevel = "debug" | "info" | "warn" | "error";

const isDebug = process.env["DEBUG"]?.includes("zero-auth") === true;
const isDev = process.env["NODE_ENV"] === "development";
const isProd = process.env["NODE_ENV"] === "production";

function shouldLog(level: LogLevel): boolean {
  if (isDebug) return true;
  if (level === "error") return true;
  if (level === "warn" && (isDev || !isProd)) return true;
  if (level === "info" && isDev) return true;
  return false;
}

function formatMessage(level: LogLevel, message: string): string {
  const prefix = "[zero-auth]";
  const ts = new Date().toISOString();
  return `${ts} ${prefix} [${level.toUpperCase()}] ${message}`;
}

export const logger = {
  debug(message: string, ...args: unknown[]): void {
    if (shouldLog("debug")) {
      console.debug(formatMessage("debug", message), ...args);
    }
  },

  info(message: string, ...args: unknown[]): void {
    if (shouldLog("info")) {
      console.info(formatMessage("info", message), ...args);
    }
  },

  warn(message: string, ...args: unknown[]): void {
    if (shouldLog("warn")) {
      console.warn(formatMessage("warn", message), ...args);
    }
  },

  error(message: string, ...args: unknown[]): void {
    if (shouldLog("error")) {
      console.error(formatMessage("error", message), ...args);
    }
  },
};
