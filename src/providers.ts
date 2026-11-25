import type { Finding } from "./report.ts";
import { classifyDatabase, isDatabaseProvider } from "./provider/database.ts";

type Effect = Pick<Finding, "class" | "reason" | "source" | "context">;
type Word = string | null;
type Prefixes = readonly (readonly string[])[];
interface Rules {
  read?: Prefixes;
  write?: Prefixes;
  local?: Prefixes;
  sensitive?: Prefixes;
  context?: readonly [string, string, string?, string?];
}

const providers: Record<string, Rules> = {
  kubectl: { read: [["get"], ["describe"], ["logs"]], write: [["apply"], ["delete"], ["exec"], ["scale"], ["patch"], ["replace"], ["create"], ["edit"], ["rollout", "restart"]], local: [["config", "use-context"]], context: ["--context", "kube_context"] },
  helm: { read: [["list"], ["status"], ["history"], ["show"]], write: [["install"], ["upgrade"], ["uninstall"], ["rollback"]], local: [["repo", "add"], ["repo", "update"]], context: ["--kube-context", "kube_context"] },
  terraform: { read: [["version"], ["workspace", "show"], ["workspace", "list"]], write: [["apply"], ["destroy"]], local: [["init"], ["fmt"], ["workspace", "select"]], context: ["--workspace", "terraform_workspace", "TF_WORKSPACE"] },
  pulumi: { read: [["version"], ["stack", "ls"]], write: [["up"], ["destroy"], ["refresh"]], local: [["stack", "select"]], context: ["--stack", "pulumi_stack", undefined, "-s"] },
  gcloud: { read: [["compute", "instances", "list"], ["compute", "instances", "describe"]], write: [["compute", "instances", "create"], ["compute", "instances", "delete"], ["run", "deploy"]], sensitive: [["auth", "print-access-token"], ["secrets", "versions", "access"]], context: ["--project", "gcloud_project", "CLOUDSDK_CORE_PROJECT"] },
  az: { read: [["vm", "list"], ["vm", "show"]], write: [["vm", "create"], ["vm", "delete"], ["deployment", "group", "create"]], sensitive: [["account", "get-access-token"], ["keyvault", "secret", "show"]], context: ["--subscription", "az_subscription"] },
  vault: { sensitive: [["read"], ["kv", "get"]], write: [["write"], ["delete"], ["kv", "put"], ["kv", "delete"]] },
  gh: { read: [["pr", "view"], ["pr", "list"], ["issue", "list"]], write: [["pr", "create"], ["pr", "merge"], ["issue", "create"], ["repo", "delete"]], sensitive: [["auth", "token"]] },
  docker: { read: [["ps"], ["images"]], write: [["push"]], local: [["build"], ["pull"], ["tag"]] },
  cdk: { write: [["deploy"], ["destroy"]], local: [["synth"]] },
  sam: { write: [["deploy"], ["delete"]], local: [["build"]] },
  serverless: { write: [["deploy"], ["remove"]] },
  "ansible-playbook": { write: [[]] },
  npm: { write: [["publish"], ["unpublish"]], read: [["view"], ["list"]] },
  yarn: { write: [["npm", "publish"], ["publish"]] },
  pnpm: { write: [["publish"]] },
  twine: { write: [["upload"]] },
  gem: { write: [["push"], ["yank"]], local: [["install"]] },
  cargo: { write: [["publish"], ["yank"]], local: [["build"], ["check"]] },
};

const aliases: Record<string, string> = { podman: "docker", sls: "serverless", mongo: "mongosh" };

export function classifyProvider(executable: string | undefined, args: readonly Word[],
  assignments?: ReadonlyMap<string, Word>): Effect | undefined {
  if (!executable) return undefined;
  const provider = Object.hasOwn(aliases, executable) ? aliases[executable] : executable;
  if (isDatabaseProvider(provider)) return { ...classifyDatabase(provider, args), source: `${provider} rules` };
  if (!Object.hasOwn(providers, provider)) return undefined;
  const rules = providers[provider];
  const words = [...args];
  const settings = rules.context;
  let context: Effect["context"];
  if (settings) {
    const [flag, key, env, alias] = settings;
    const assigned = env ? assignments?.get(env) : undefined;
    let value: Word = assigned !== undefined ? assigned : env ? process.env[env] ?? null : null;
    for (let i = 0; i < words.length;) {
      const current = words[i];
      if (current === flag || (alias && current === alias)) value = words.splice(i, 2)[1] ?? null;
      else if (current && (current.startsWith(`${flag}=`) || (alias && current.startsWith(`${alias}=`)))) {
        value = current.slice(current.indexOf("=") + 1);
        words.splice(i, 1);
      } else i++;
    }
    if (value && /^[\w.:-]+$/.test(value)) context = { [key]: value };
  }
  const result = (classification: Effect["class"], reason: string): Effect =>
    ({ class: classification, reason, source: `${provider} rules`, ...(context && { context }) });
  const matches = (patterns?: Prefixes) =>
    patterns?.some((pattern) => pattern.every((part, index) => words[index] === part));
  if (provider === "kubectl" && words[0] === "get") {
    const resource = words[1];
    if (resource && /^(?:secret|secrets)(?:[/.]|$)/.test(resource)) {
      return result("SENSITIVE", "may return Kubernetes secret values");
    }
    if (!resource || !/^(?:pod|pods|po|deployment|deployments|deploy|service|services|svc|node|nodes|no|namespace|namespaces|ns)(?:\/[^,]+)?$/.test(resource)) {
      return result("UNKNOWN", "Kubernetes resource is ambiguous");
    }
  }
  if (matches(rules.write)) return result("DANGEROUS", `can change remote state via ${provider}`);
  if (matches(rules.sensitive)) return result("SENSITIVE", `can return credentials or secret values via ${provider}`);
  if (matches(rules.local)) return result("LOCAL", `can change local state via ${provider}`);
  if (matches(rules.read) && !words.includes(null)) return result("READ-ONLY", `recognized read operation via ${provider}`);
  return result("UNKNOWN", `unrecognized or ambiguous ${provider} operation`);
}
