import { classifyCliOverride, sdkServiceForCli } from "./cli-rules.ts";
import { classifyAwsEffect } from "./effects.ts";
import { classifyCliOperation, loadOfflineSnapshot, unknownAws } from "./operations.ts";
import type { AwsEffect } from "./operations.ts";
import { awsPermissions } from "../report.ts";

type Word = string | null;
const valued = new Set([
  "--region", "--profile", "--output", "--endpoint-url", "--query", "--ca-bundle",
  "--cli-read-timeout", "--cli-connect-timeout", "--cli-binary-format", "--color",
]);
const switches = new Set([
  "--debug", "--no-cli-pager", "--no-sign-request", "--no-verify-ssl", "--no-paginate",
  "--cli-auto-prompt", "--no-cli-auto-prompt",
]);

/**
 * Splits off the global options of an `aws` command line. Returns the remaining words (service,
 * operation, arguments) and the `--profile` value when one was given, or undefined when a
 * global option is missing its value.
 */
export function awsArguments(words: readonly Word[]): { argv: Word[]; profile?: Word } | undefined {
  const argv: Word[] = [];
  const result: { argv: Word[]; profile?: Word } = { argv };
  for (let i = 1; i < words.length; i++) {
    const word = words[i];
    if (word === null) {
      argv.push(word);
      continue;
    }
    const idx = word.indexOf("=");
    const flag = idx < 0 ? word : word.slice(0, idx);
    if (valued.has(flag)) {
      const value = idx < 0 ? words[++i] : word.slice(idx + 1);
      if (value === undefined) return undefined;
      if (flag === "--profile") result.profile = value;
    } else if (!switches.has(word)) argv.push(word);
  }
  return result;
}

export async function classifyAws(words: readonly Word[], assignedProfile?: Word): Promise<AwsEffect> {
  const parsed = awsArguments(words);
  if (!parsed) return unknownAws("AWS global option has no value");
  const { argv } = parsed;
  let profile = assignedProfile === undefined ? process.env.AWS_PROFILE : assignedProfile ?? undefined;
  if ("profile" in parsed) profile = parsed.profile ?? undefined;
  const [service, verb, ...args] = argv;
  let effect = classifyCliOverride(argv);
  if (!effect && service && verb) {
    effect = classifyAwsEffect(sdkServiceForCli(service), verb,
      args.includes("--with-decryption") ? true : args.includes(null) ? undefined : false);
    if (effect) {
      const snapshot = await loadOfflineSnapshot();
      const mapped = snapshot && classifyCliOperation(snapshot, sdkServiceForCli(service), verb);
      const permissions = mapped?.[awsPermissions] ?? {
        actions: [], unknown: "AWS data snapshot unavailable or invalid",
      };
      effect = {
        ...effect,
        ...(effect.class !== "UNKNOWN" ? { source: "AWS CLI override" } : {}),
        [awsPermissions]: effect.class === "UNKNOWN" ? {
          ...permissions, unknown: [effect.reason, permissions.unknown].filter(Boolean).join("; "),
        } : permissions,
      };
    }
  }
  if (!effect) {
    if (service === null || verb === null) {
      effect = unknownAws("command is in a variable");
    } else if (!service || !verb || !/^[a-z][a-z0-9-]*$/.test(service) || !/^[a-z][a-z0-9-]*$/.test(verb)) {
      effect = unknownAws("AWS service or operation is missing or invalid");
    } else {
      const snapshot = await loadOfflineSnapshot();
      effect = snapshot
        ? classifyCliOperation(snapshot, sdkServiceForCli(service), verb)
        : unknownAws("AWS data snapshot unavailable or invalid");
    }
  }
  if (!effect[awsPermissions]) {
    effect = { ...effect, [awsPermissions]: { actions: [], unknown: "AWS CLI helper or command is not mapped to IAM actions" } };
  }
  return {
    ...effect,
    reason: args.includes("--dry-run") ? `${effect.reason}; --dry-run present` : effect.reason,
    ...(profile && /^[a-zA-Z0-9_.-]+$/.test(profile) ? { context: { profile } } : {}),
  };
}
