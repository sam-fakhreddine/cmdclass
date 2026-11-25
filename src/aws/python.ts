import { classifyAwsEffect } from "./effects.ts";
import { classifyOperation, unknownAws } from "./operations.ts";
import type { AwsEffect } from "./operations.ts";
import type { Snapshot } from "../aws-data.ts";

export function classifySdkMethod(
  snapshot: Snapshot | undefined, service: string, method: string,
  args: { target?: string; decrypt?: boolean; dryRun?: boolean; unpacked?: boolean },
): AwsEffect {
  const helper = (classification: AwsEffect["class"], reason: string): AwsEffect =>
    ({ class: classification, reason, source: "Boto3 helper" });
  if (method === "get_waiter" && args.target) return helper("READ-ONLY", "waiter reads a resource condition");
  if (method === "get_paginator") {
    if (!args.target) return unknownAws("paginator operation is dynamic");
    method = args.target;
  }
  if (service === "s3") {
    if (["generate_presigned_url", "generate_presigned_post"].includes(method)) {
      return helper("DANGEROUS", "creates a signed access link");
    }
    if (["upload_file", "upload_fileobj", "copy"].includes(method)) {
      return helper("DANGEROUS", "writes to S3");
    }
    if (["download_file", "download_fileobj"].includes(method)) {
      return helper("LOCAL", "downloads to a local destination");
    }
  }
  const override = classifyAwsEffect(service, method.replaceAll("_", "-"), args.unpacked ? undefined : args.decrypt);
  const mapping = snapshot?.methods[`${service}:${method}`];
  const effect = override ?? (snapshot && mapping ? classifyOperation(snapshot, ...mapping) :
    unknownAws(snapshot ? `method not in AWS data snapshot ${snapshot.date}` : "AWS data snapshot unavailable or invalid"));
  return args.dryRun ? { ...effect, reason: `${effect.reason}; DryRun present` } : effect;
}
