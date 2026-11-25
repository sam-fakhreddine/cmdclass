export interface SourceWord {
  start: number;
  end: number;
  // The parser supplies the static prefix, stopping at the first expansion.
  prefix: string;
}

const credentialFlags = new Set([
  "--password", "--token", "--secret", "--client-secret", "--access-key", "--secret-access-key",
]);
const credentialName = /(?:^|_)(?:PASSWORD|PASSWD|TOKEN|SECRET|ACCESS_KEY|ACCESS_KEY_ID|API_KEY|PRIVATE_KEY)(?:_|$)/i;
const urlWithUserInfo = /[a-z][a-z0-9+.-]*:\/\/[^/?#@\s]+@/i;
const marker = "<redacted>";

export function redactCommand(source: string, words: readonly SourceWord[]): string {
  let output = "";
  let cursor = 0;
  let redactNext = false;
  for (const { start, end, prefix } of words) {
    if (!Number.isInteger(start) || !Number.isInteger(end) ||
        start < cursor || end <= start || end > source.length) {
      throw new RangeError("Invalid source word span");
    }
    const raw = source.slice(start, end);
    const equals = prefix.indexOf("=");
    const key = equals < 0 ? prefix : prefix.slice(0, equals);
    const isAssignment = equals >= 0 && /^[a-z_][a-z0-9_]*$/i.test(key) && credentialName.test(key);
    let display = raw;
    if (redactNext) {
      display = marker;
    } else if (equals >= 0 && (credentialFlags.has(key) || isAssignment)) {
      display = `${key}=${marker}`;
    } else if (urlWithUserInfo.test(prefix) || urlWithUserInfo.test(raw)) {
      display = marker;
    }
    redactNext = equals < 0 && credentialFlags.has(key);
    output += source.slice(cursor, start) + display;
    cursor = end;
  }
  return output + source.slice(cursor);
}
