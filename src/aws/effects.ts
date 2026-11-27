import { unknownAws } from "./operations.ts";
import type { AwsEffect } from "./operations.ts";

const effects = new Map<string, [AwsEffect["class"], string]>([
  ["iam:create-access-key", ["MUTATING", "creates a long-lived AWS access key"]],
  ["iam:create-login-profile", ["MUTATING", "creates IAM console credentials"]],
  ["iam:create-service-specific-credential", ["MUTATING", "creates a long-lived service credential"]],
  ["secretsmanager:get-secret-value", ["SENSITIVE", "returns an existing secret value"]],
  ["secretsmanager:batch-get-secret-value", ["SENSITIVE", "returns existing secret values"]],
  ["kms:decrypt", ["SENSITIVE", "returns decrypted plaintext"]],
  ["sts:assume-role", ["SENSITIVE", "returns temporary AWS credentials"]],
  ["sts:assume-role-with-saml", ["SENSITIVE", "returns temporary AWS credentials"]],
  ["sts:assume-role-with-web-identity", ["SENSITIVE", "returns temporary AWS credentials"]],
  ["sts:get-session-token", ["SENSITIVE", "returns temporary AWS credentials"]],
  ["sts:get-federation-token", ["SENSITIVE", "returns temporary AWS credentials"]],
  ["ecr:get-authorization-token", ["SENSITIVE", "returns a registry authorization token"]],
  ["rds:generate-db-auth-token", ["SENSITIVE", "creates a short-lived database token"]],
  ["codeartifact:get-authorization-token", ["SENSITIVE", "returns a short-lived authorization token"]],
  ["ssm:start-session", ["MUTATING", "opens a session on a remote host"]],
]);
export const dynamicDecryptionReason = "SSM decryption option is dynamic";
const parameterReads = new Set(["get-parameter", "get-parameters", "get-parameters-by-path"]);

export function classifyAwsEffect(service: string, verb: string, decrypt: boolean | undefined): AwsEffect | undefined {
  const override = (classification: AwsEffect["class"], reason: string): AwsEffect =>
    ({ class: classification, reason, source: "AWS operation override" });
  if (service === "ssm" && parameterReads.has(verb)) {
    if (decrypt === undefined) return unknownAws(dynamicDecryptionReason);
    return decrypt ? override("SENSITIVE", "returns decrypted parameter values") :
      override("READ-ONLY", "reads parameters without decryption");
  }
  const effect = effects.get(`${service}:${verb}`);
  return effect && override(...effect);
}
