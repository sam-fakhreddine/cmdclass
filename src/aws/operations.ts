import { readSnapshot } from "../aws-data.ts";
import type { Snapshot } from "../aws-data.ts";
import type { Finding } from "../report.ts";
import { awsPermissions } from "../report.ts";

export type AwsEffect = Pick<Finding, "class" | "reason" | "source" | "context" | typeof awsPermissions>;
export const unknownAws = (reason: string): AwsEffect =>
  ({ class: "UNKNOWN", reason, source: "AWS", [awsPermissions]: { actions: [], unknown: reason } });

export function operationPermissions(snapshot: Snapshot, service: string, operation: string): NonNullable<Finding[typeof awsPermissions]> {
  const mapped = snapshot.operations[`${service}:${operation}`];
  if (!mapped?.length) return { actions: [], unknown: "operation has no IAM action mapping in the snapshot" };
  const actions = [...new Set(mapped.filter((action) => Object.hasOwn(snapshot.actions, action)))].sort();
  return {
    actions,
    ...(actions.length !== new Set(mapped).size ? { unknown: "operation has incomplete IAM action mappings in the snapshot" } : {}),
  };
}

let offline: Promise<Snapshot | undefined> | undefined;
export function loadOfflineSnapshot(): Promise<Snapshot | undefined> {
  offline ??= readSnapshot().catch(() => undefined);
  return offline;
}

export function classifyOperation(snapshot: Snapshot, service: string, operation: string): AwsEffect {
  const key = `${service}:${operation}`;
  const permissions = operationPermissions(snapshot, service, operation);
  if (signedAccessOperations.has(key)) {
    return { class: "MUTATING", reason: "creates a signed access link", source: "AWS operation override", [awsPermissions]: permissions };
  }
  if (temporaryCredentialOperations.has(key)) {
    return { class: "SENSITIVE", reason: "returns temporary AWS credentials or access tokens", source: "AWS operation override", [awsPermissions]: permissions };
  }
  return { ...classifyIamOperation(snapshot, service, operation), [awsPermissions]: permissions };
}

const signedAccessOperations = new Set([
  "airflow-serverless:CreateAirflowUiUrl",
  "athena:CreatePresignedNotebookUrl",
  "elasticmapreduce:GetOnClusterAppUIPresignedURL",
  "elasticmapreduce:GetPersistentAppUIPresignedURL",
  "kinesisanalytics:CreateApplicationPresignedUrl",
  "qapps:CreatePresignedUrl",
  "sagemaker:CreateHubContentPresignedUrls",
  "sagemaker:CreatePartnerAppPresignedUrl",
  "sagemaker:CreatePresignedDomainUrl",
  "sagemaker:CreatePresignedMlflowAppUrl",
  "sagemaker:CreatePresignedMlflowTrackingServerUrl",
  "sagemaker:CreatePresignedNotebookInstanceUrl",
]);
const temporaryCredentialOperations = new Set([
  "signin:CreateOAuth2Token",
  "signin:CreateOAuth2TokenWithIAM",
]);

export function classifyIamOperation(snapshot: Snapshot, service: string, operation: string): AwsEffect {
  const key = `${service}:${operation}`;
  const actions = (snapshot.operations[key] ?? [key]).slice().sort();
  const data = actions.map((action) => ({ action, access: snapshot.actions[action] }));
  const danger = data.find(({ access }) => access && access !== "Read" && access !== "List");
  if (!danger && (!data.length || data.some(({ access }) => !access))) {
    return unknownAws(`not in AWS data snapshot ${snapshot.date}`);
  }
  const { action, access } = danger ?? data[0];
  const source = `IAM ${action} (${access})`;
  return { class: danger ? "MUTATING" : "READ-ONLY", reason: source, source };
}

interface SdkIndex {
  namespaces: Map<string, Set<string>>;
  methods: Set<string>;
  /** SDK service names that define each method. */
  services: Map<string, string[]>;
}
const sdkIndexes = new WeakMap<Snapshot, SdkIndex>();

export function sdkIndex(snapshot: Snapshot): {
  namespaces: ReadonlyMap<string, ReadonlySet<string>>;
  methods: ReadonlySet<string>;
  services: ReadonlyMap<string, readonly string[]>;
} {
  let index = sdkIndexes.get(snapshot);
  if (!index) {
    index = { namespaces: new Map(), methods: new Set(), services: new Map() };
    for (const [key, [namespace]] of Object.entries(snapshot.methods)) {
      const separator = key.indexOf(":");
      const service = key.slice(0, separator);
      const method = key.slice(separator + 1);
      index.methods.add(method);
      const services = index.services.get(method);
      if (services) services.push(service);
      else index.services.set(method, [service]);
      let candidates = index.namespaces.get(service);
      if (!candidates) index.namespaces.set(service, candidates = new Set());
      candidates.add(namespace);
    }
    sdkIndexes.set(snapshot, index);
  }
  return index;
}

export function classifyCliOperation(snapshot: Snapshot, sdkService: string, verb: string): AwsEffect {
  const method = snapshot.methods[`${sdkService}:${verb.replaceAll("-", "_")}`];
  if (method) return classifyOperation(snapshot, ...method);

  const candidates = sdkIndex(snapshot).namespaces.get(sdkService);
  if (candidates && candidates.size > 1) return unknownAws(`AWS service mapping is ambiguous in snapshot ${snapshot.date}`);
  const namespace = candidates?.values().next().value ?? sdkService;
  const api = verb.replace(/(^|-)([a-z0-9])/g, (_, __, letter: string) => letter.toUpperCase());
  return classifyOperation(snapshot, namespace, api);
}
