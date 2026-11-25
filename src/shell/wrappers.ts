type Word = string | null;
type Options = { switches: readonly string[]; valued?: readonly string[] };

const wrappers = new Map<string, Options>([
  ["sudo", { switches: ["-E", "--preserve-env", "-n", "--non-interactive"], valued: ["-u", "--user", "-g", "--group"] }],
  ["env", { switches: [] }],
  ["timeout", { switches: ["--foreground", "--preserve-status", "-v", "--verbose"],
    valued: ["-s", "--signal", "-k", "--kill-after"] }],
  ["nohup", { switches: [] }],
  ["time", { switches: ["-p"] }],
  ["command", { switches: ["-p"] }],
  ["exec", { switches: ["-l"], valued: ["-a"] }],
  ["xargs", {
    switches: ["-0", "--null", "-r", "--no-run-if-empty", "-t", "--verbose", "-x", "--exit"],
    valued: ["-n", "--max-args", "-P", "--max-procs", "-s", "--max-chars", "-L", "--max-lines"],
  }],
]);

export function unwrap(input: readonly Word[], assignments: Map<string, Word>,
  onWrapper?: (name: string) => void): readonly Word[] {
  let words = input;
  for (;;) {
    const name = words[0]?.split("/").at(-1);
    const options = name && wrappers.get(name);
    if (!name || !options) return words;
    let offset = 1;
    while (offset < words.length) {
      const word = words[offset];
      if (word === null) return words;
      if (word === "--") {
        offset++;
        break;
      }
      if (!word.startsWith("-") || word === "-") break;
      const equals = word.indexOf("=");
      const flag = equals < 0 ? word : word.slice(0, equals);
      if (options.valued?.includes(flag)) {
        if (equals >= 0 && flag.startsWith("--") && equals < word.length - 1) offset++;
        else if (equals < 0 && words[offset + 1] && !words[offset + 1]?.startsWith("-")) offset += 2;
        else return words;
      } else if (options.switches.includes(word)) offset++;
      else return words;
    }
    if (name === "env" || name === "sudo") {
      for (;;) {
        const match = /^([a-z_]\w*)=([\s\S]*)$/i.exec(words[offset] ?? "");
        if (!match) break;
        assignments.set(match[1], match[2]);
        offset++;
      }
    }
    if (name === "timeout") {
      if (!/^(?:\d+(?:\.\d+)?|\.\d+)[smhd]?$/.test(words[offset] ?? "")) return words;
      offset++;
    }
    if (offset >= words.length) return words;
    onWrapper?.(name);
    words = words.slice(offset);
  }
}
