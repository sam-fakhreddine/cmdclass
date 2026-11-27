import { awsPermissions, oneLine } from "./report.ts";
import type { Report, UnknownKind } from "./report.ts";

type Location = { path: string; line: number; column: number };
type Unknown = Location & { reason: string; unknown_kind?: UnknownKind };

export function buildPermissionsReport(
  files: readonly { path: string; report: Report }[],
  errors: readonly { path: string; message: string }[],
  snapshotDate: string | null,
) {
  const actions = new Map<string, Location[]>();
  const unknown: Unknown[] = [];
  for (const { path, report } of files) {
    for (const entry of report.entries) {
      const location = { path, line: entry.line, column: entry.column };
      const permissions = entry[awsPermissions];
      for (const action of permissions?.actions ?? []) {
        const locations = actions.get(action) ?? [];
        locations.push(location);
        actions.set(action, locations);
      }
      const reason = permissions?.unknown ?? (entry.class === "UNKNOWN" ? entry.reason : undefined);
      if (reason) unknown.push({ ...location, reason, ...(entry.unknown_kind ? { unknown_kind: entry.unknown_kind } : {}) });
    }
  }
  for (const error of errors) unknown.push({ path: error.path, line: 0, column: 0, reason: error.message });
  const byLocation = (a: Location, b: Location) =>
    a.path.localeCompare(b.path) || a.line - b.line || a.column - b.column;
  return {
    schema_version: 1 as const,
    snapshot_date: snapshotDate,
    actions: [...actions].sort(([a], [b]) => a.localeCompare(b))
      .map(([action, locations]) => ({ action, locations: locations.sort(byLocation) })),
    resources: "UNKNOWN" as const,
    unknown: unknown.sort(byLocation),
    limitations: [
      "Candidate actions are not a proven minimum and can include conditional actions.",
      "Resources are not inferred. Dynamic code, subprocesses, runtime conditions, and downstream calls can require additional permissions.",
      "A call on a client that cannot be traced is listed as UNKNOWN, with candidate actions when the method is distinctive; it adds no action to the list.",
      "Directory scans skip hidden entries, symlinks, and excluded directories. Only imports of project modules found beside or above a script are followed.",
    ],
  };
}

export function formatPermissionsReport(report: ReturnType<typeof buildPermissionsReport>): string {
  const lines = [
    `AWS candidate permissions (snapshot: ${report.snapshot_date ?? "UNKNOWN"})`,
    ...report.actions.map(({ action }) => `  ${oneLine(action)}`),
    `resources: ${report.resources}`,
    ...report.unknown.map(({ path, line, column, reason, unknown_kind }) =>
      `UNKNOWN ${oneLine(path)}${line ? `:${line}:${column}` : ""}: ${unknown_kind ? `${unknown_kind}: ` : ""}${oneLine(reason)}`),
    ...report.limitations,
  ];
  return `${lines.join("\n")}\n`;
}
