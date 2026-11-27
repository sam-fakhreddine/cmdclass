import type { Classification } from "../report.ts";

type Effect = { class: Classification; reason: string };
const sqlTools = new Set(["psql", "mysql"]);
const redisReads = new Set(["EXISTS", "TTL", "PTTL", "TYPE", "DBSIZE", "PING"]);
const redisWrites = new Set(["DEL", "UNLINK", "SET", "MSET", "FLUSHALL", "FLUSHDB", "EXPIRE", "RENAME", "EVAL", "EVALSHA"]);

export function isDatabaseProvider(provider: string | undefined): boolean {
  return !!provider && (sqlTools.has(provider) || ["mongosh", "mongo", "redis-cli"].includes(provider));
}

export function classifyDatabase(provider: string, args: readonly (string | null)[]): Effect {
  const unknown: Effect = { class: "UNKNOWN", reason: "database operation is unsupported or ambiguous" };
  const write: Effect = { class: "MUTATING", reason: "may change remote database state" };
  const read: Effect = { class: "READ-ONLY", reason: "recognized read-only database operation" };
  if (args.some((arg) => arg === null)) return unknown;
  if (provider === "redis-cli") {
    const operation = args[0]?.toUpperCase();
    if (operation && redisWrites.has(operation)) return write;
    if (operation && redisReads.has(operation)) return read;
    return unknown;
  }
  if (!sqlTools.has(provider)) return unknown;
  const noStartup = provider === "psql" ? ["-X", "--no-psqlrc"] : ["--no-defaults"];
  const explicitStartupBypass = noStartup.includes(args[0] ?? "");
  const command = explicitStartupBypass ? args.slice(1) : args;
  if (command.length !== 2) return unknown;
  const [flag, statement] = command;
  if (!statement || !(provider === "psql" ? ["-c", "--command"] : ["-e", "--execute"]).includes(flag ?? "")) return unknown;
  if (/^\s*(?:INSERT|UPDATE|DELETE|TRUNCATE|CREATE|ALTER|DROP|GRANT|REVOKE|REPLACE)\b/i.test(statement)) return write;
  // Only an isolated numeric projection is safe here; SQL SELECT can invoke
  // functions, create tables, or be followed by another statement.
  if (explicitStartupBypass && /^\s*SELECT\s+[0-9]+\s*;?\s*$/i.test(statement)) return read;
  return unknown;
}
