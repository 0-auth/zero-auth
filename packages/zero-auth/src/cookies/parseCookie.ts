/**
 * Zero-dependency, pure-function cookie header parser.
 *
 * Parses a raw `Cookie` HTTP header string into a plain key-value object.
 * Values are URI-decoded. Malformed pairs are silently skipped.
 *
 * @example
 * ```ts
 * parseCookieHeader("access_token=abc123; refresh_token=xyz789");
 * // => { access_token: "abc123", refresh_token: "xyz789" }
 * ```
 */
export function parseCookieHeader(header: string): Record<string, string> {
  const result: Record<string, string> = Object.create(null);

  if (!header) return result;

  for (const pair of header.split(";")) {
    const eqIdx = pair.indexOf("=");
    if (eqIdx === -1) continue;

    const key = pair.slice(0, eqIdx).trim();
    const rawVal = pair.slice(eqIdx + 1).trim();

    if (!key) continue;

    try {
      result[key] = decodeURIComponent(rawVal);
    } catch {
      // If decoding fails, store the raw value.
      result[key] = rawVal;
    }
  }

  return result;
}
