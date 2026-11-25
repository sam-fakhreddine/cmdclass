export const classes = ["DANGEROUS", "SENSITIVE", "UNKNOWN", "LOCAL", "READ-ONLY"] as const;
export type Classification = typeof classes[number];

export interface Finding {
  line: number;
  column: number;
  command: string;
  class: Classification;
  reason: string;
  source: string;
  context?: Readonly<Record<string, string>>;
}

export function emptySummary(): Record<Classification, number> {
  return {
    DANGEROUS: 0,
    SENSITIVE: 0,
    UNKNOWN: 0,
    LOCAL: 0,
    "READ-ONLY": 0,
  };
}

export function buildReport(findings: readonly Finding[]) {
  const entries = [...findings].sort((a, b) =>
    classes.indexOf(a.class) - classes.indexOf(b.class) ||
    a.line - b.line || a.column - b.column);
  const summary = emptySummary();
  for (const entry of entries) summary[entry.class]++;
  return { schema_version: 1 as const, entries, summary };
}

export type Report = ReturnType<typeof buildReport>;

export function reportExitCode({ summary }: Pick<Report, "summary">): 0 | 1 | 3 {
  if (summary.DANGEROUS || summary.UNKNOWN || summary.LOCAL) return 1;
  return summary.SENSITIVE ? 3 : 0;
}

// Keep source text on one line and escape terminal control characters.
export function oneLine(value: string): string {
  return value.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu,
    (character) => JSON.stringify(character).slice(1, -1) === character
      ? `\\u{${character.codePointAt(0)?.toString(16)}}`
      : JSON.stringify(character).slice(1, -1));
}

export function formatSummary(summary: Report["summary"]): string {
  return `summary: ${[...classes].reverse().map(
    (classification) => `${summary[classification]} ${classification.toLowerCase()}`,
  ).join(", ")}`;
}

export function formatReport(report: Report, json: boolean): string {
  if (json) return `${JSON.stringify(report)}\n`;
  const lines = report.entries.map((entry) => {
    const context = Object.entries(entry.context ?? {})
      .map(([key, value]) => `${key}: ${value}`).join(", ");
    return oneLine(`${entry.class.padEnd(10)} ${entry.line}:${entry.column}  ${
      entry.command}  ${entry.reason}${context ? `  ${context}` : ""}`);
  });
  lines.push(formatSummary(report.summary));
  return `${lines.join("\n")}\n`;
}
