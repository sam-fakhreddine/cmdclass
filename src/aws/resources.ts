import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

interface ResourceAction { operation: string; result?: string }
interface Shape {
  constructors: Record<string, string>;
  collections: Record<string, string>;
  actions: Record<string, ResourceAction>;
  batch: Record<string, ResourceAction>;
}
type Services = Record<string, { path: string; shapes: Record<string, Shape> }>;
interface Catalog { sha256: string; services: Services }
let cached: Promise<Services> | undefined;

export function loadResources(): Promise<Services> {
  cached ??= readFile(new URL("../../data/boto3-resources.json", import.meta.url), "utf8").then((raw) => {
    const { services, sha256 }: Catalog = JSON.parse(raw);
    if (!services || createHash("sha256").update(JSON.stringify(services)).digest("hex") !== sha256) {
      throw new Error("invalid Boto3 resource snapshot");
    }
    return services;
  });
  return cached;
}

export function resourceShape(catalog: Services, service: string | undefined, shape: string | undefined): Shape | undefined {
  if (!service || !Object.hasOwn(catalog, service)) return;
  const shapes = catalog[service].shapes;
  const key = shape ?? "$service";
  return Object.hasOwn(shapes, key) ? shapes[key] : undefined;
}
