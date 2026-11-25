import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

type Access = "Write" | "Read" | "List" | "Permissions management" | "Tagging";
interface Reference {
  actions: Record<string, Access>;
  operations: Record<string, string[]>;
  methods: Record<string, [string, string]>;
}
export interface Snapshot extends Reference { date: string; sha256: string }

const endpoint = "https://servicereference.us-east-1.amazonaws.com/v1/";
const snapshotPath = fileURLToPath(new URL("../data/aws.json", import.meta.url));
const digest = (data: Reference) => createHash("sha256").update(JSON.stringify(data)).digest("hex");
const symbol = (x: unknown): x is string => typeof x === "string" && /^[a-z0-9_-]+$/i.test(x);
const record = (x: unknown): x is Record<string, unknown> => !!x && typeof x === "object" && !Array.isArray(x);
const accessLevels = new Set(["Write", "Read", "List", "Permissions management", "Tagging"]);

function isReference(x: unknown): x is Reference {
  return record(x) && record(x.actions) && record(x.operations) && record(x.methods) &&
    Object.values(x.actions).every((v) => typeof v === "string" && accessLevels.has(v)) &&
    Object.values(x.operations).every((v) => Array.isArray(v) && v.every((s) => typeof s === "string")) &&
    Object.values(x.methods).every((v) => Array.isArray(v) && v.length === 2 && v.every(symbol));
}

export async function readSnapshot(path = snapshotPath): Promise<Snapshot> {
  const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
  if (!isReference(parsed) || !("date" in parsed) || !("sha256" in parsed) ||
      typeof parsed.date !== "string" || !/^\d{4}-\d\d-\d\d$/.test(parsed.date) ||
      typeof parsed.sha256 !== "string" ||
      digest({ actions: parsed.actions, operations: parsed.operations, methods: parsed.methods }) !== parsed.sha256) {
    throw new Error("invalid AWS data snapshot");
  }
  return { ...parsed, date: parsed.date, sha256: parsed.sha256 };
}

export function projectReference(files: readonly unknown[]): Reference {
  const actions: Reference["actions"] = Object.create(null);
  const operations: Reference["operations"] = Object.create(null);
  const methods: Reference["methods"] = Object.create(null);
  const ambiguous = new Set<string>();
  for (const service of files) {
    if (!record(service) || !symbol(service.Name) || !Array.isArray(service.Actions) ||
        (service.Operations !== undefined && !Array.isArray(service.Operations))) throw new Error("invalid AWS service");
    const namespace = service.Name;
    for (const x of service.Actions) {
      if (!record(x) || !symbol(x.Name) || !record(x.Annotations) ||
          !record(x.Annotations.Properties)) continue;
      const { IsWrite, IsList, IsPermissionManagement, IsTaggingOnly } = x.Annotations.Properties;
      if ([IsWrite, IsList, IsPermissionManagement, IsTaggingOnly].some((v) => typeof v !== "boolean")) continue;
      actions[`${namespace}:${x.Name}`] =
        IsPermissionManagement ? "Permissions management" :
          IsWrite ? "Write" : IsTaggingOnly ? "Tagging" : IsList ? "List" : "Read";
    }
    for (const op of service.Operations ?? []) {
      if (!record(op) || !symbol(op.Name)) throw new Error("invalid AWS operation");
      const name = op.Name;
      operations[`${namespace}:${name}`] = Array.isArray(op.AuthorizedActions)
        ? op.AuthorizedActions.map((action) =>
          record(action) && symbol(action.Name) && symbol(action.Service)
            ? `${action.Service}:${action.Name}` : "")
        : [];
      if (Array.isArray(op.SDK)) for (const entry of op.SDK) {
        if (!record(entry) || entry.Package !== "Boto3" || !symbol(entry.Name) || !symbol(entry.Method)) continue;
        const key = `${entry.Name}:${entry.Method}`;
        if (ambiguous.has(key)) continue;
        const prior = methods[key];
        if (prior && (prior[0] !== namespace || prior[1] !== name)) {
          delete methods[key];
          ambiguous.add(key);
        } else methods[key] = [namespace, name];
      }
    }
  }
  return { actions, operations, methods };
}

async function download(path: string): Promise<unknown> {
  const response = await fetch(new URL(path, endpoint), { redirect: "error", signal: AbortSignal.timeout(20000) });
  if (!response.ok) throw new Error(`AWS Service Reference returned HTTP ${response.status}`);
  return response.json();
}

export async function updateSnapshot(path = snapshotPath, get = download): Promise<void> {
  const listing = await get("service-list.json");
  if (!Array.isArray(listing) || !listing.length ||
      !listing.every((row) => record(row) && symbol(row.service))) throw new Error("invalid AWS service list");
  const names: string[] = [...new Set<string>(listing.map((row) => row.service))].sort();
  const files = [];
  for (let i = 0; i < names.length; i += 12) {
    files.push(...await Promise.all(names.slice(i, i + 12).map((name) => get(`${name}/${name}.json`))));
  }
  const data = projectReference(files);
  if (!Object.keys(data.actions).length || !Object.keys(data.operations).length) throw new Error("empty AWS access data");
  const payload = JSON.stringify({ ...data, date: new Date().toISOString().slice(0, 10), sha256: digest(data) });
  await mkdir(dirname(path), { recursive: true });
  const pending = `${path}.${randomUUID()}.tmp`;
  try {
    await writeFile(pending, `${payload}\n`, { flag: "wx" });
    await readSnapshot(pending);
    await rename(pending, path);
  } finally {
    await rm(pending, { force: true });
  }
}
