import { unknownAws } from "./operations.ts";
import type { AwsEffect } from "./operations.ts";

type Word = string | null;

const simple: Record<string, [AwsEffect["class"], string]> = {
  "s3:presign": ["MUTATING", "creates a signed download link"],
  "ecr:get-login-password": ["SENSITIVE", "returns a registry login password"],
  "sso:login": ["LOCAL", "updates the local AWS SSO login cache"],
  "configure:set": ["LOCAL", "updates local AWS configuration"],
  "configure:list": ["READ-ONLY", "lists local AWS configuration"],
  "eks:update-kubeconfig": ["LOCAL", "updates local kubeconfig"],
  "cloudformation:deploy": ["MUTATING", "deploys a CloudFormation stack"],
  "cloudformation:package": ["MUTATING", "may upload CloudFormation artifacts"],
  "logs:tail": ["READ-ONLY", "reads CloudWatch logs"],
  "s3:ls": ["READ-ONLY", "lists S3 objects or buckets"],
};

// CLI command groups that use a different name from the SDK; keys and values
// are not IAM namespaces. The snapshot owns SDK-to-IAM resolution.
const cliToSdkService = new Map([
  ["s3api", "s3"], // AWS CLI separates API operations from its high-level S3 commands.
  ["configservice", "config"], // AWS CLI and Boto3 use different names for AWS Config.
]);

export function sdkServiceForCli(service: string): string {
  return cliToSdkService.get(service) ?? service;
}

export function classifyCliOverride(argv: readonly Word[]): AwsEffect | undefined {
  const [service, verb, ...args] = argv;
  const hand = (classification: AwsEffect["class"], reason: string): AwsEffect =>
    ({ class: classification, reason, source: "AWS CLI override" });
  const key = `${service}:${verb}`;
  if ((service === "--version" || service === "help") && argv.length === 1 ||
      verb === "help" && argv.length === 2 || args.length === 1 && args[0] === "help") {
    return hand("READ-ONLY", "displays AWS CLI help or version");
  }
  if (!service || !verb) return undefined;
  if (Object.hasOwn(simple, key)) {
    return hand(...simple[key]);
  } else if (service === "s3" && ["rm", "mv", "mb", "rb", "website"].includes(verb)) {
    return hand("MUTATING", "changes S3 resources");
  } else if (service === "s3" && ["cp", "sync"].includes(verb)) {
    const source = args[0];
    const target = args[1];
    return target?.startsWith("s3://") ? hand("MUTATING", "writes to S3") :
      target && !target.startsWith("-") && source?.startsWith("s3://") ? hand("LOCAL", "downloads to a local destination") :
        unknownAws("S3 transfer direction is not known");
  } else if (verb === "wait" && /^[a-z][a-z0-9-]*$/.test(args[0] ?? "")) {
    return hand("READ-ONLY", "waits for a resource condition");
  }
  return undefined;
}
