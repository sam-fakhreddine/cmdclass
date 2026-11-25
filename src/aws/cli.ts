import { classifyCliOverride, sdkServiceForCli } from "./cli-rules.ts";
import { classifyAwsEffect } from "./effects.ts";
import { classifyCliOperation, loadOfflineSnapshot, unknownAws } from "./operations.ts";
import type { AwsEffect } from "./operations.ts";

type Word = string | null;
const valued = new Set([
  "--region", "--profile", "--output", "--endpoint-url", "--query", "--ca-bundle",
  "--cli-read-timeout", "--cli-connect-timeout", "--cli-binary-format", "--color",
]);
const switches = new Set([
  "--debug", "--no-cli-pager", "--no-sign-request", "--no-verify-ssl", "--no-paginate",
  "--cli-auto-prompt", "--no-cli-auto-prompt",
]);

export async function classifyAws(words: readonly Word[], assignedProfile?: Word): Promise<AwsEffect> {
  const argv: Word[] = [];
  let profile = assignedProfile === undefined ? process.env.AWS_PROFILE : assignedProfile ?? undefined;
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
      if (value === undefined) return unknownAws("AWS global option has no value");
      if (flag === "--profile") profile = value ?? undefined;
    } else if (!switches.has(word)) argv.push(word);
  }
  const [service, verb, ...args] = argv;
  let effect = classifyCliOverride(argv);
  if (!effect && service && verb) {
    effect = classifyAwsEffect(sdkServiceForCli(service), verb,
      args.includes("--with-decryption") ? true : args.includes(null) ? undefined : false);
    if (effect && effect.class !== "UNKNOWN") effect = { ...effect, source: "AWS CLI override" };
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
  return {
    ...effect,
    reason: args.includes("--dry-run") ? `${effect.reason}; --dry-run present` : effect.reason,
    ...(profile && /^[a-zA-Z0-9_.-]+$/.test(profile) ? { context: { profile } } : {}),
  };
}
