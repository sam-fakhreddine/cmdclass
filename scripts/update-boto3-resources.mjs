import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { createHash } from "node:crypto";

const revision = process.argv[2] ?? "4a91d785ac613b42bbc7528b176f8cc8d9307319";
if (!/^[a-f0-9]{40}$/.test(revision)) throw new Error("Provide an immutable Boto3 commit SHA");
const repo = "repos/boto/boto3";
const api = (...args) => execFileSync("gh", ["api", ...args], { encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
const get = (path) => api("-H", "Accept: application/vnd.github.raw+json", `${repo}/contents/${path}?ref=${revision}`);
const snake = (name) => name.replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
  .replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
const tree = JSON.parse(api(`${repo}/git/trees/${revision}?recursive=1`));
if (tree.truncated) throw new Error("Incomplete Boto3 source tree");
const paths = new Map();
for (const { path } of tree.tree.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0)) {
  const service = /^boto3\/data\/([a-z0-9-]+)\/[\d-]+\/resources-1\.json$/.exec(path)?.[1];
  if (service) paths.set(service, path);
}
if (!paths.size) throw new Error("No Boto3 resource models found");

const services = {};
for (const [service, path] of paths) {
  const model = JSON.parse(get(path));
  if (!model.service || !model.resources) throw new Error(`Not a Boto3 resource model: ${path}`);
  const shapes = {};
  for (const [shape, data] of Object.entries({ $service: model.service, ...model.resources })) {
    const relations = Object.entries(data.has ?? {}).filter(([, entry]) => entry.resource?.type);
    // At the service root Boto3 exposes every model unless it has an explicit relation.
    const explicitTypes = new Set(relations.map(([, entry]) => entry.resource.type));
    const constructors = Object.fromEntries([
      ...(shape === "$service" ? Object.keys(model.resources)
        .filter((name) => !explicitTypes.has(name)).map((name) => [name, name]) : []),
      ...relations.filter(([, entry]) => !(entry.resource.identifiers ?? []).some((id) => id.source === "data"))
        .map(([name, entry]) => [name, entry.resource.type]),
    ]);
    const collections = Object.fromEntries(Object.entries(data.hasMany ?? {})
      .filter(([, entry]) => entry.resource?.type)
      .map(([name, entry]) => [snake(name), entry.resource.type]));
    const actions = (entries) => Object.fromEntries(Object.entries(entries ?? {})
      .filter(([, entry]) => entry.request?.operation)
      .map(([name, entry]) => [snake(name), { operation: entry.request.operation, result: entry.resource?.type }]));
    shapes[shape] = { constructors, collections, actions: actions(data.actions), batch: actions(data.batchActions) };
  }
  services[service] = { path, shapes };
}
const sha256 = createHash("sha256").update(JSON.stringify(services)).digest("hex");
for (const name of ["LICENSE", "NOTICE"]) {
  writeFileSync(new URL(`../data/boto3-${name}`, import.meta.url), get(name));
}
writeFileSync(new URL("../data/boto3-resources.json", import.meta.url), `${JSON.stringify({ revision, sha256, services })}\n`);
