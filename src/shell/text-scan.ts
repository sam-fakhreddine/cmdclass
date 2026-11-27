import type { Node } from "web-tree-sitter";
import { awsArguments, classifyAws } from "../aws/cli.ts";
import { awsPermissions } from "../report.ts";
import type { Finding } from "../report.ts";

type Range = readonly [start: number, end: number];

// `aws` as a word of its own, followed by something that can start a service name or option.
const awsWord = /(?<![\w.$-])aws[ \t]+(?=[a-z-])/g;
const operationName = /^[a-z][a-z0-9-]*$/;
const maxScannedWords = 16;
const textScanReason = "AWS command in script text, not confirmed as executed";

function commentRanges(root: Node): Range[] {
  const ranges: Range[] = [];
  const work = [root];
  while (work.length) {
    const node = work.pop()!;
    if (node.type === "comment") ranges.push([node.startIndex, node.endIndex]);
    else work.push(...node.namedChildren);
  }
  return ranges;
}

/** The words that follow `aws` on its line, up to the first shell operator; dynamic words become null. */
function followingWords(source: string, start: number): (string | null)[] {
  const lineEnd = source.indexOf("\n", start);
  const words: (string | null)[] = [];
  for (const raw of source.slice(start, lineEnd < 0 ? source.length : lineEnd).split(/\s+/)) {
    if (!raw) continue;
    if (/^[|;&()<>\\]/.test(raw) || words.length >= maxScannedWords) break;
    const word = raw.replace(/^["']+|["');|&]+$/g, "");
    words.push(/[$`*?{}[\]]/.test(word) ? null : word);
    if (/["');|&]$/.test(raw)) break;
  }
  return words;
}

/**
 * A backstop for the syntax walk: finds `aws <service> <operation>` anywhere in the script text
 * that no analysed command accounts for, such as a command held in a string or written into a
 * heredoc. Whether that text ever runs is not known, so each hit is UNKNOWN and names the
 * operation it would be. `covered` holds the source ranges of commands already analysed.
 */
export async function scanAwsText(source: string, root: Node, covered: readonly Range[]): Promise<Finding[]> {
  const skipped = [...covered, ...commentRanges(root)];
  const findings: Finding[] = [];
  for (const match of source.matchAll(awsWord)) {
    const index = match.index;
    if (skipped.some(([start, end]) => index >= start && index < end)) continue;
    const words = ["aws", ...followingWords(source, index + match[0].length)];
    const [service, operation] = awsArguments(words)?.argv ?? [];
    if (!service || !operation || !operationName.test(service) || !operationName.test(operation)) continue;
    const effect = await classifyAws(words, null);
    const permissions = effect[awsPermissions];
    // Prose such as "the aws cli to ..." names no real operation: it has no class and no mapped action.
    if (effect.class === "UNKNOWN" && !permissions?.actions.length) continue;
    const before = source.slice(0, index);
    const note = "found in script text; execution not confirmed";
    findings.push({
      line: before.split("\n").length, column: index - before.lastIndexOf("\n"),
      command: `aws ${service} ${operation}`, class: "UNKNOWN",
      reason: `${textScanReason}: ${effect.reason}`, source: "text scan", unknown_kind: "INLINE",
      [awsPermissions]: {
        actions: permissions?.actions ?? [], unknown: permissions?.unknown ? `${note}; ${permissions.unknown}` : note,
      },
    });
  }
  return findings;
}
