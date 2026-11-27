import { classifyAwsEffect } from "./effects.ts";
import { classifyOperation, operationPermissions, sdkIndex, unknownAws } from "./operations.ts";
import type { AwsEffect } from "./operations.ts";
import type { Snapshot } from "../aws-data.ts";
import { awsPermissions } from "../report.ts";

/** Client methods that boto3 adds on top of the service API. */
export const sdkHelperMethods: ReadonlySet<string> = new Set([
  "get_paginator", "get_waiter", "generate_presigned_url", "generate_presigned_post",
  "upload_file", "upload_fileobj", "download_file", "download_fileobj",
]);
const maxCandidateServices = 3;
export const dynamicPaginatorReason = "paginator operation is dynamic";

export const sessionCredentialsEffect: AwsEffect = {
  class: "SENSITIVE", reason: "returns AWS credentials from the session", source: "Boto3 helper",
  [awsPermissions]: { actions: [], unknown: "Boto3 helper is not mapped to IAM actions" },
};

function candidateHint(snapshot: Snapshot, method: string): string | undefined {
  const services = sdkIndex(snapshot).services.get(method);
  if (!services) return undefined;
  if (services.length > maxCandidateServices) return `the method exists in ${services.length} AWS services`;
  const actions = new Set<string>();
  for (const service of services) {
    for (const action of operationPermissions(snapshot, ...snapshot.methods[`${service}:${method}`]).actions) {
      actions.add(action);
    }
  }
  return actions.size ? `if this is an AWS client call, candidate actions: ${[...actions].sort().join(", ")}` : undefined;
}

/**
 * An SDK-shaped call on a receiver that could not be traced to a client. The permissions note
 * names candidate actions when the method belongs to few services; none are added as findings.
 */
export function unknownClientEffect(
  snapshot: Snapshot | undefined, method: string, target: string | undefined, origin: string | undefined,
  candidateService?: string,
): AwsEffect {
  const reason = origin ? `client type not known (${origin})` : "client type not known";
  const operation = method === "get_paginator" ? target : method;
  const mapping = candidateService && operation ? snapshot?.methods[`${candidateService}:${operation}`] : undefined;
  let hint: string | undefined;
  if (snapshot && mapping) {
    const actions = operationPermissions(snapshot, ...mapping).actions;
    if (actions.length) hint = `if the receiver is a boto3 session, candidate actions: ${actions.join(", ")}`;
  } else if (snapshot && operation) hint = candidateHint(snapshot, operation);
  return {
    class: "UNKNOWN", reason, source: "AWS",
    [awsPermissions]: { actions: [], unknown: hint ? `${reason}; ${hint}` : reason },
  };
}

export function classifySdkMethod(
  snapshot: Snapshot | undefined, service: string, method: string,
  args: { target?: string; decrypt?: boolean; dryRun?: boolean; unpacked?: boolean },
): AwsEffect {
  const helper = (classification: AwsEffect["class"], reason: string): AwsEffect =>
    ({ class: classification, reason, source: "Boto3 helper",
      [awsPermissions]: { actions: [], unknown: "Boto3 helper is not mapped to IAM actions" } });
  if (method === "get_waiter" && args.target) return helper("READ-ONLY", "waiter reads a resource condition");
  if (method === "get_paginator") {
    if (!args.target) return unknownAws(dynamicPaginatorReason);
    method = args.target;
  }
  if (service === "s3") {
    if (["generate_presigned_url", "generate_presigned_post"].includes(method)) {
      return helper("MUTATING", "creates a signed access link");
    }
    if (["upload_file", "upload_fileobj", "copy"].includes(method)) {
      return helper("MUTATING", "writes to S3");
    }
    if (["download_file", "download_fileobj"].includes(method)) {
      return helper("LOCAL", "downloads to a local destination");
    }
  }
  const override = classifyAwsEffect(service, method.replaceAll("_", "-"), args.unpacked ? undefined : args.decrypt);
  const mapping = snapshot?.methods[`${service}:${method}`];
  const mapped = snapshot && mapping ? classifyOperation(snapshot, ...mapping) :
    unknownAws(snapshot ? `method not in AWS data snapshot ${snapshot.date}` : "AWS data snapshot unavailable or invalid");
  const permissions = mapped[awsPermissions];
  const effect = override ? {
    ...override,
    [awsPermissions]: override.class === "UNKNOWN" ? {
      actions: permissions?.actions ?? [],
      unknown: [override.reason, permissions?.unknown].filter(Boolean).join("; "),
    } : permissions,
  } : mapped;
  return args.dryRun ? { ...effect, reason: `${effect.reason}; DryRun present` } : effect;
}
