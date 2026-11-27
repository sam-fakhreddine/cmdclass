import type { Node } from "web-tree-sitter";
import { classifyAws } from "./aws/cli.ts";
import {
  classifySdkMethod, dynamicPaginatorReason, sdkHelperMethods, sessionCredentialsEffect, unknownClientEffect,
} from "./aws/python.ts";
import { dynamicDecryptionReason } from "./aws/effects.ts";
import { classifyOperation, loadOfflineSnapshot, sdkIndex, unknownAws } from "./aws/operations.ts";
import type { AwsEffect } from "./aws/operations.ts";
import { loadResources, resourceShape } from "./aws/resources.ts";
import type { Finding } from "./report.ts";
import { InputError, withSyntax } from "./syntax.ts";
import {
  agree, annotatedReturn, argumentsOf, awsModule, bindImports, bindingReach, calleeFor, calleeOf, classAttribute,
  classBases, classOf, mergeReach, reachOf,
  field, findMethod, identifier, isHandle, isNone, literal, resolve, sessionTypePaths, signature, simpleString,
  trackedModule, unknown,
} from "./python/bindings.ts";
import type {
  Binding, Carry, ClassRef, ClassSummary, FunctionSummary, Lookup, ModuleSummary, ProcessWrapper, Reach, Scope,
  UnknownOrigin,
} from "./python/bindings.ts";
import { callArguments, deferredCall, indexDefinitions, mapArguments } from "./python/definitions.ts";
import type { FunctionInfo } from "./python/definitions.ts";
import { importRequests, portable, submoduleName } from "./python/modules.ts";
import type { LoadedModule, ModuleLoader } from "./python/modules.ts";

const processLaunchPaths = new Set([
  "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call",
  "subprocess.check_output", "subprocess.getoutput", "subprocess.getstatusoutput",
  "os.system", "os.popen", "asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell",
  // Replacing or spawning a process is a launch too.
  "os.execl", "os.execle", "os.execlp", "os.execlpe", "os.execv", "os.execve", "os.execvp", "os.execvpe",
  "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe", "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
  "os.posix_spawn", "os.posix_spawnp", "os.startfile", "pty.spawn",
]);
const argvProcessPaths = new Set([
  "subprocess.run", "subprocess.Popen", "subprocess.call",
  "subprocess.check_call", "subprocess.check_output",
]);
const branches = new Set(["if_statement", "for_statement", "while_statement", "try_statement", "match_statement"]);
const comprehensions = new Set([
  "list_comprehension", "dictionary_comprehension", "set_comprehension", "generator_expression",
]);
/** Receiver expressions that are values, never an SDK client. */
const valueExpressions = new Set([
  "string", "concatenated_string", "integer", "float", "true", "false", "none", "list", "dictionary", "set",
  "tuple", "list_comprehension", "dictionary_comprehension", "set_comprehension", "generator_expression", "lambda",
]);
// Facts flow one call or attribute hop per round, so this bounds how deep a client is followed.
const maxRounds = 8;
const maxImportDepth = 3;
const maxClassDepth = 5;
const callerNote = "client inferred from call sites in this file";
const referenceNote = "method reference, call site not analysed";
const importedNote = "in an imported function";

export interface PythonOptions {
  /** Resolves project modules so imported client factories and helpers can be followed. */
  loadModule?: ModuleLoader;
}
interface Round {
  findings: Finding[];
  /** The function each finding was found in, parallel to `findings`. */
  owners: (number | undefined)[];
  processes: { owner: number | undefined; run: () => Promise<Finding | undefined> }[];
  /** Which functions each function calls or defines. */
  edges: Map<number, Set<number>>;
  next: Carry;
}

const emptyCarry = (): Carry => ({
  parameters: new Map(), returns: new Map(), attributes: new Map(), moduleScope: new Map(),
  returnReach: new Map(), called: new Set(),
});

function carrySignature(carry: Carry): string {
  const entries = (map: ReadonlyMap<string | number, Binding>) =>
    [...map].map(([key, value]) => `${key}=${signature(value)}`).sort().join("|");
  const nested = (map: ReadonlyMap<number, ReadonlyMap<string, Binding>>) =>
    [...map].map(([key, value]) => `${key}{${entries(value)}}`).sort().join("|");
  const reaches = [...carry.returnReach].map(([key, reach]) => `${key}=${reach}`).sort().join("|");
  return [nested(carry.parameters), entries(carry.returns), nested(carry.attributes), entries(carry.moduleScope),
    reaches, [...carry.called].sort().join("|")].join("#");
}

/** One binding for a name assigned in several places. */
function settle(values: readonly Binding[]): Binding {
  const agreed = agree(values);
  if (agreed) {
    if (agreed.kind !== "unknown" || agreed.instanceOf) return agreed;
    const { candidateService } = agreed;
    return { kind: "unknown", origin: agreed.origin, reach: bindingReach(agreed), ...(candidateService ? { candidateService } : {}) };
  }
  if (values.every(isNone)) return { kind: "unknown", origin: "unresolved assignment", none: true };
  const reach = mergeReach(values.filter((value) => !isNone(value)).map(bindingReach));
  if (values.some((value) => value.kind === "client" || value.kind === "resource")) return { kind: "client", reach };
  return unknown("unresolved assignment", reach);
}

/** Drops a service parameter that names a parameter of some other function. */
function detach(binding: Binding, parameters?: readonly { name: string }[]): Binding {
  if (binding.kind === "tuple") {
    return { kind: "tuple", items: binding.items.map((item) => item && detach(item, parameters)) };
  }
  if (!isHandle(binding) || !binding.serviceParameter) return binding;
  if (parameters?.some((parameter) => parameter.name === binding.serviceParameter)) return binding;
  const { serviceParameter: _dropped, ...rest } = binding;
  return rest;
}

const carriesValue = (binding: Binding | undefined): binding is Binding =>
  isHandle(binding) || binding?.kind === "tuple" || binding?.kind === "literal" ||
  (binding?.kind === "unknown" && (binding.instanceOf !== undefined || binding.candidateService !== undefined));

function withNote(binding: Binding, note: string): Binding {
  if (binding.kind === "tuple") return { kind: "tuple", items: binding.items.map((item) => item && withNote(item, note)) };
  if (binding.kind !== "literal" && binding.kind !== "unknown" && !isHandle(binding)) return binding;
  if (binding.note?.includes(note)) return binding;
  return { ...binding, note: binding.note ? `${binding.note}; ${note}` : note };
}

const summaries = new Map<string, ModuleSummary | undefined>();

async function summarize(module: LoadedModule, chain: readonly string[]): Promise<ModuleSummary | undefined> {
  if (summaries.has(module.key)) return summaries.get(module.key);
  if (chain.includes(module.key) || chain.length >= maxImportDepth) return undefined;
  let summary: ModuleSummary | undefined;
  try {
    summary = (await analyzeModule(module.source, module.loader, [...chain, module.key])).summary;
  } catch (error) {
    // An import that does not parse stays an untracked import; the importing file is still analysed.
    if (!(error instanceof InputError)) throw error;
  }
  summaries.set(module.key, summary);
  return summary;
}

async function loadImports(root: Node, loader: ModuleLoader, chain: readonly string[]) {
  const imports = new Map<string, ModuleSummary>();
  const load = async (name: string) => {
    const loaded = await loader(name);
    const summary = loaded && await summarize(loaded, chain);
    if (summary) imports.set(name, summary);
    return loaded;
  };
  for (const request of importRequests(root)) {
    const loaded = await load(request.module);
    if (!loaded?.package && !/^\.+$/.test(request.module)) continue;
    for (const name of request.names) await load(submoduleName(request.module, name));
  }
  return imports;
}

export async function analyzePython(source: string, options: PythonOptions = {}): Promise<Finding[]> {
  return (await analyzeModule(source, options.loadModule, [])).findings;
}

async function analyzeModule(
  source: string, loader: ModuleLoader | undefined, chain: readonly string[],
): Promise<{ findings: Finding[]; summary: ModuleSummary }> {
  return withSyntax("python", source, async (root) => {
    const [snapshot, catalog] = await Promise.all([loadOfflineSnapshot(), loadResources()]);
    const sdk = snapshot && sdkIndex(snapshot);
    const definitions = indexDefinitions(root);
    const imports = loader ? await loadImports(root, loader, chain) : new Map<string, ModuleSummary>();

    function runRound(carry: Carry): Round {
      const findings: Finding[] = [];
      const owners: (number | undefined)[] = [];
      const processes = new Map<number, Round["processes"][number]>();
      const edges = new Map<number, Set<number>>();
      const sites = new Map<number, (Map<string, Binding> | undefined)[]>();
      const returned = new Map<number, Binding[]>();
      const attributes = new Map<number, Map<string, Binding[]>>();
      const globals = new Map<string, Binding[]>();
      const lookup: Lookup = { catalog, definitions, carry, imports };
      const moduleScope: Scope = new Map();
      const stubbed = new Set<Binding>();
      let mocked = false;
      let currentFunction: FunctionInfo | undefined;
      let currentClass: Node | undefined;
      let currentReceiver: string | undefined;
      let declaredGlobals = new Set<string>();

      /** `reach` says where an UNKNOWN effect's uncertainty comes from; it is ignored for other classes. */
      function emit(node: Node, method: string, effect: AwsEffect, receiver?: Binding, reach?: Reach) {
        const kind = reach === "external" ? "EXTERNAL CALL" as const : "INLINE" as const;
        const context = receiver && "context" in receiver ? receiver.context : undefined;
        let reason = effect.reason;
        if (isHandle(receiver)) {
          for (const note of new Set([receiver.note, receiver.serviceNote])) if (note) reason = `${reason}; ${note}`;
        }
        if (mocked || (receiver && stubbed.has(receiver))) reason = `${reason}; inside a test`;
        findings.push({
          line: node.startPosition.row + 1, column: node.startPosition.column + 1,
          command: `${method}(...)`, ...effect, ...(context && { context }), reason,
          ...(effect.class === "UNKNOWN" && reach ? { unknown_kind: kind } : {}),
        });
        owners.push(currentFunction?.key);
      }

      function importedPath(node: Node | null, scope: Scope) {
        const binding = resolve(node?.type === "call" ? field(node, "function") : node, scope, lookup);
        return binding?.kind === "module" ? binding.path : undefined;
      }

      function processArgument(call: Node, scope: Scope) {
        if (!argvProcessPaths.has(importedPath(field(call, "function"), scope) ?? "")) return undefined;
        const { args } = argumentsOf(call);
        const positional = args.filter((arg) => arg.type !== "keyword_argument");
        if (positional.length !== 1 || positional[0].type === "list_splat" ||
            positional[0].type === "dictionary_splat") return undefined;
        for (const arg of args.filter((item) => item.type === "keyword_argument")) {
          const key = field(arg, "name")?.text;
          const value = field(arg, "value");
          if (key === "shell" && value?.type === "false") continue;
          if (!key || !["capture_output", "text", "timeout", "check", "encoding", "errors"].includes(key) ||
              !value || !["true", "false", "integer", "float", "none", "string"].includes(value.type) ||
              (value.type === "string" && simpleString(value) === undefined)) return undefined;
        }
        return positional[0];
      }

      function wrapperFor(node: Node, scope: Scope): ProcessWrapper | undefined {
        if (node.parent?.type !== "module") return undefined;
        const params = field(node, "parameters")?.namedChildren ?? [];
        const restNode = params.at(-1);
        const rest = restNode?.type === "list_splat_pattern" ? identifier(restNode.firstNamedChild) : undefined;
        if (!rest || params.slice(0, -1).some((parameter) => parameter.type !== "identifier")) return undefined;
        const statements = field(node, "body")?.namedChildren.filter((entry) => entry.type !== "comment") ?? [];
        const assignment = statements[0]?.type === "expression_statement" ? statements[0].firstNamedChild : null;
        const target = identifier(field(assignment, "left"));
        const command = field(assignment, "right");
        if (assignment?.type !== "assignment" || !target || !command ||
            !["list", "tuple"].includes(command.type)) return undefined;
        const statement = statements[1];
        let process = statement?.type === "return_statement" || statement?.type === "expression_statement"
          ? statement.firstNamedChild : null;
        if (process?.type === "assignment") process = field(process, "right");
        if (process?.type !== "call" || identifier(processArgument(process, scope) ?? null) !== target) return undefined;
        return { parameters: params.slice(0, -1).map((parameter) => parameter.text), rest, command, process };
      }

      const unknownSpread = Symbol("unknown spread");
      type ProcessWord = string | null | typeof unknownSpread;
      function commandWords(command: Node, values?: ReadonlyMap<string, string | null>,
        restName?: string, rest: ProcessWord[] = []): (string | null)[] | undefined {
        if (!["list", "tuple"].includes(command.type)) return undefined;
        const words: (string | null)[] = [];
        for (const item of command.namedChildren) {
          const tokens: ProcessWord[] = item.type === "list_splat"
            ? restName !== undefined && identifier(item.firstNamedChild) === restName ? rest : [unknownSpread]
            : [values?.get(item.text) ?? simpleString(item) ?? null];
          for (const token of tokens) {
            if (token === unknownSpread) return [...words, null];
            words.push(token);
          }
        }
        return words;
      }

      function recordAwsProcess(node: Node, words: (string | null)[] | undefined) {
        if (!words || words[0] !== "aws") return;
        const line = node.startPosition.row + 1;
        const column = node.startPosition.column + 1;
        // Deferred so that only the final round's subprocess commands are classified.
        processes.set(node.startIndex, {
          owner: currentFunction?.key,
          run: () => classifyAws(words, null).then((effect) => {
            if (effect.class === "UNKNOWN") return undefined;
            return {
              ...effect, line, column, command: "aws(...)",
              reason: `${effect.reason}; via Python subprocess`, source: effect.source,
            };
          }),
        });
      }

      function inspectProcessWrapper(node: Node, wrapper: ProcessWrapper, scope: Scope) {
        if (!processArgument(wrapper.process, scope)) return;
        const { args } = argumentsOf(node);
        const values = new Map<string, string | null>();
        const rest: ProcessWord[] = [];
        for (const arg of args) {
          if (arg.type === "keyword_argument" || arg.type === "dictionary_splat") return;
          if (arg.type === "list_splat") {
            if (values.size < wrapper.parameters.length) return;
            rest.push(unknownSpread);
            break;
          }
          if (values.size < wrapper.parameters.length) {
            values.set(wrapper.parameters[values.size], simpleString(arg) ?? null);
          } else rest.push(simpleString(arg) ?? null);
        }
        if (values.size !== wrapper.parameters.length) return;
        recordAwsProcess(node, commandWords(wrapper.command, values, wrapper.rest, rest));
      }

      function sdkEffect(node: Node, scope: Scope | undefined, service: string, method: string) {
        const { args, keyword, unpacked } = argumentsOf(node);
        const decrypt = keyword("WithDecryption");
        const target = args[0] ?? null;
        return classifySdkMethod(snapshot, service, method, {
          target: scope ? literal(target, scope) : simpleString(target), unpacked,
          decrypt: !decrypt || decrypt.type === "false" ? false : decrypt.type === "true" ? true : undefined,
          dryRun: keyword("DryRun")?.type === "true",
        });
      }

      function push<K, V>(map: Map<K, V[]>, key: K, value: V) {
        const values = map.get(key);
        if (values) values.push(value);
        else map.set(key, [value]);
      }

      function addEdge(from: number, to: number) {
        const targets = edges.get(from);
        if (targets) targets.add(to);
        else edges.set(from, new Set([to]));
      }

      /** Records what this call passes to a function defined here, and what an imported one does. */
      function recordCallee(node: Node, scope: Scope) {
        const deferred = deferredCall(node);
        const callee = deferred ? calleeFor(deferred.target, scope, lookup) : calleeOf(node, scope, lookup);
        if (!callee) return;
        for (const candidate of callee.ambiguous ?? []) push(sites, candidate.key, undefined);
        for (const effect of callee.summary?.effects ?? []) {
          findings.push({
            ...effect, line: node.startPosition.row + 1, column: node.startPosition.column + 1,
            reason: effect.reason.includes(importedNote) ? effect.reason : `${effect.reason}; ${importedNote}`,
          });
          owners.push(currentFunction?.key);
        }
        if (!callee.info) return;
        if (currentFunction) addEdge(currentFunction.key, callee.info.key);
        const written = deferred ? deferred.args : callArguments(node);
        const mapped = mapArguments(written, callee.info.parameters, callee.bound);
        const declared = callee.info.parameters;
        push(sites, callee.info.key, mapped && new Map([...mapped].map(([parameter, argument]) => {
          const text = simpleString(argument);
          const omittedNone = !argument && declared.some((entry) => entry.name === parameter && entry.defaultsToNone);
          let passed: Binding | undefined;
          if (omittedNone || argument?.type === "none") passed = { kind: "unknown", origin: "unresolved assignment", none: true };
          else if (text !== undefined) passed = { kind: "literal", value: text };
          else if (argument) passed = resolve(argument, scope, lookup);
          return [parameter, detach(passed ?? unknown("unresolved assignment"))];
        })));
      }

      function isLocalMember(receiver: Binding | undefined, method: string) {
        if (receiver?.kind !== "unknown") return false;
        const owner = receiver.instanceOf ?? classOf(receiver);
        return owner !== undefined && findMethod(owner, method, lookup) !== undefined;
      }

      /** Why a receiver could not be traced, or undefined when it cannot be an SDK client at all. */
      function untraced(node: Node, receiver: Binding | undefined): { origin?: UnknownOrigin } | undefined {
        if (receiver?.kind === "unknown") return { origin: receiver.origin };
        if (receiver?.kind === "module") {
          return trackedModule.test(receiver.path) ? undefined : { origin: "untracked import" };
        }
        if (receiver || valueExpressions.has(node.type)) return undefined;
        if (node.type === "identifier") return { origin: "unresolved name" };
        if (node.type === "attribute") return { origin: "unresolved attribute" };
        return { origin: node.type === "call" ? "unresolved call result" : "unresolved expression" };
      }

      const awsEvidence = (scope: Scope) => [...scope.values()].some((value) =>
        isHandle(value) || (value.kind === "module" && awsModule.test(value.path)));
      const isArgument = (node: Node) => node.parent?.type === "argument_list" ||
        (node.parent?.type === "keyword_argument" && field(node.parent, "value")?.id === node.id);
      const inSnapshot = (service: string, method: string) =>
        snapshot !== undefined && Object.hasOwn(snapshot.methods, `${service}:${method}`);

      /** An SDK-shaped method used on `receiverNode`: called, or passed along as a bound method. */
      function inspectSdkUse(node: Node, receiverNode: Node, method: string, scope: Scope, reference: boolean) {
        const receiver = resolve(receiverNode, scope, lookup);
        if (receiver?.kind === "session") {
          if (!reference && method === "get_credentials") emit(node, method, sessionCredentialsEffect, receiver);
          return;
        }
        const distinctive = method.includes("_") && !sdkHelperMethods.has(method);
        if (receiver?.kind !== "client" && receiver?.kind !== "resource") {
          const trace = untraced(receiverNode, receiver);
          const sdkShaped = sdk?.methods.has(method) || sdkHelperMethods.has(method);
          if (!trace || !sdkShaped || isLocalMember(receiver, method) || (!distinctive && !awsEvidence(scope))) return;
          if (reference && (!distinctive || !isArgument(node))) return;
          const target = reference ? undefined : simpleString(argumentsOf(node).args[0] ?? null);
          const candidate = receiver?.kind === "unknown" ? receiver.candidateService : undefined;
          const reach = receiver ? bindingReach(receiver) : reachOf(receiverNode, scope, lookup);
          emit(node, method, unknownClientEffect(snapshot, method, target, trace.origin, candidate), undefined, reach);
          return;
        }
        if (reference) {
          if (receiver.kind !== "client" || !distinctive) return;
          if (!receiver.service) {
            if (sdk?.methods.has(method) && isArgument(node)) {
              emit(node, method, unknownAws("service is in a variable"), receiver, bindingReach(receiver));
            }
            return;
          }
          if (!inSnapshot(receiver.service, method)) return;
          const effect = classifySdkMethod(snapshot, receiver.service, method, {});
          emit(node, method, { ...effect, reason: `${effect.reason}; ${referenceNote}` }, receiver);
          return;
        }
        if (!receiver.service) {
          emit(node, method, unknownAws("service is in a variable"), receiver, bindingReach(receiver));
          return;
        }
        let effect: AwsEffect;
        if (receiver.kind === "resource") {
          const shape = resourceShape(catalog, receiver.service, receiver.shape);
          const actions = receiver.collection ? shape?.batch : shape?.actions;
          const action = actions && Object.hasOwn(actions, method) ? actions[method] : undefined;
          if (!action && resolve(node, scope, lookup)?.kind === "resource") return;
          const namespaces = sdk?.namespaces.get(receiver.service);
          const namespace = namespaces?.values().next().value ?? receiver.service;
          effect = action && snapshot && (namespaces?.size ?? 0) <= 1
            ? classifyOperation(snapshot, namespace, action.operation) : unknownAws("resource operation is not mapped");
        } else effect = sdkEffect(node, scope, receiver.service, method);
        emit(node, method, effect, receiver, dynamicArgumentReach(node, scope, effect));
      }

      /** For an UNKNOWN caused by a dynamic argument, where that argument's value comes from. */
      function dynamicArgumentReach(node: Node, scope: Scope, effect: AwsEffect): Reach | undefined {
        if (effect.class !== "UNKNOWN") return undefined;
        const { args, keyword } = argumentsOf(node);
        if (effect.reason.startsWith(dynamicPaginatorReason)) return reachOf(args[0] ?? null, scope, lookup);
        if (!effect.reason.startsWith(dynamicDecryptionReason)) return undefined;
        const option = keyword("WithDecryption") ?? args.find((argument) => argument.type === "dictionary_splat");
        return reachOf(option ?? null, scope, lookup);
      }

      function inspectCall(node: Node, scope: Scope) {
        const fn = field(node, "function");
        const path = importedPath(fn, scope);
        if (path && processLaunchPaths.has(path)) {
          emit(node, path, {
            class: "UNKNOWN", reason: "Python subprocess command is not analysed", source: "Python process launch",
          }, undefined, "external");
          const argument = processArgument(node, scope);
          if (argument) recordAwsProcess(node, commandWords(argument));
          return;
        }
        recordCallee(node, scope);
        const name = identifier(fn);
        const bound = name && scope.get(name);
        if (bound && bound.kind === "process-wrapper") inspectProcessWrapper(node, bound.wrapper, scope);
        if (bound && bound.kind === "forwarder") {
          const { args, keyword } = argumentsOf(node);
          const argument = args.length === 1 && args[0].type !== "keyword_argument" ? args[0] : null;
          const receiver = args.length === 1 ? resolve(keyword(bound.parameter) ?? argument, scope, lookup) : undefined;
          if (receiver?.kind === "client" && receiver.service) {
            const effect = sdkEffect(bound.call, undefined, receiver.service, bound.method);
            emit(node, bound.method, { ...effect, reason: `${effect.reason}; via ${name}()` }, receiver);
          }
        }
        if (fn?.type === "call" && identifier(field(fn, "function")) === "getattr") {
          const target = resolve(argumentsOf(fn).args[0] ?? null, scope, lookup);
          if (target?.kind === "client" || target?.kind === "resource") {
            const named = argumentsOf(fn).args[1] ?? null;
            emit(node, "getattr", unknownAws("method name is dynamic"), target, reachOf(named, scope, lookup));
          }
        }
        const method = identifier(field(fn, "attribute"));
        const receiverNode = field(fn, "object");
        if (method && receiverNode) inspectSdkUse(node, receiverNode, method, scope, false);
      }

      function recordAttribute(owner: Node, name: string, binding: Binding) {
        let names = attributes.get(owner.startIndex);
        if (!names) attributes.set(owner.startIndex, names = new Map());
        push(names, name, binding);
      }

      function store(target: Node, binding: Binding, scope: Scope) {
        if (target.type === "subscript") {
          if (isHandle(binding)) scope.set(target.text, binding);
          else scope.delete(target.text);
          return;
        }
        if (target.type !== "identifier" && target.type !== "attribute") return;
        scope.set(target.text, binding);
        if (target.type === "identifier") {
          if (currentFunction && declaredGlobals.has(target.text)) push(globals, target.text, binding);
          if (currentClass && !currentFunction) recordAttribute(currentClass, target.text, binding);
          return;
        }
        const member = field(target, "attribute")?.text;
        const object = identifier(field(target, "object"));
        if (currentClass && member && object !== undefined && object === currentReceiver) {
          recordAttribute(currentClass, member, binding);
        }
      }

      function assign(node: Node, scope: Scope) {
        const left = field(node, "left");
        const right = field(node, "right");
        if (!left) return;
        const plain = node.type === "assignment";
        if (left.type === "pattern_list" || left.type === "tuple_pattern") {
          const value = plain ? resolve(right, scope, lookup) : undefined;
          const items = value?.kind === "tuple" ? value.items : [];
          const reach = plain ? reachOf(right, scope, lookup) : "inline";
          left.namedChildren.forEach((target, position) =>
            store(target, items[position] ?? unknown("unresolved assignment", reach), scope));
          return;
        }
        if (!["identifier", "attribute", "subscript"].includes(left.type)) return;
        const value = plain ? literal(right, scope) : undefined;
        const resolved = plain ? resolve(right, scope, lookup) : undefined;
        if (value !== undefined) {
          const named = right ? scope.get(right.text) : undefined;
          store(left, { kind: "literal", value, ...(named?.kind === "literal" && named.note ? { note: named.note } : {}) }, scope);
        } else if (resolved) store(left, resolved, scope);
        else if (plain && right?.type === "none") store(left, { kind: "unknown", origin: "unresolved assignment", none: true }, scope);
        else {
          const reach = plain ? reachOf(right, scope, lookup) : "inline";
          const wasClient = scope.get(left.text)?.kind === "client";
          store(left, wasClient ? { kind: "client", reach } : unknown("unresolved assignment", reach), scope);
        }
      }

      function bindLoopTargets(target: Node | null, scope: Scope, reach: Reach) {
        if (!target) return;
        if (target.type === "identifier") scope.set(target.text, unknown("unresolved assignment", reach));
        else for (const child of target.namedChildren) bindLoopTargets(child, scope, reach);
      }

      /** A comprehension has its own scope; its loop variables take their reach from what they iterate. */
      function visitComprehension(node: Node, scope: Scope) {
        const inner = new Map(scope);
        for (const clause of node.namedChildren) {
          if (clause.type !== "for_in_clause") continue;
          bindLoopTargets(field(clause, "left"), inner, reachOf(field(clause, "right"), inner, lookup));
        }
        for (const child of node.namedChildren) visit(child, inner);
      }

      function parameterBinding(parameter: Node, name: string, scope: Scope, info: FunctionInfo | undefined): Binding {
        const annotationNode = field(parameter, "type");
        const annotation = annotationNode?.text;
        const annotated = annotationNode?.firstNamedChild ?? null;
        const forward = simpleString(annotated);
        const annotationBinding = forward === undefined ? resolve(annotated, scope, lookup) : scope.get(forward);
        if (annotationBinding?.kind === "module" && sessionTypePaths.has(annotationBinding.path)) {
          return { kind: "session" };
        }
        const service = annotation && /^([a-zA-Z0-9]+)Client$/.exec(annotation)?.[1]?.toLowerCase();
        if (service && sdk?.namespaces.has(service)) return { kind: "client", service };
        const owner = classOf(annotationBinding);
        // Every caller of a private function that does not escape is in this file.
        const callersVisible = info !== undefined && info.private && !info.escapes && carry.called.has(info.key);
        return {
          kind: "unknown", origin: annotation ? "unsupported parameter annotation" : "untyped function parameter",
          parameterOf: info?.key, parameterName: name, reach: callersVisible ? "inline" : "external",
          ...(owner ? { instanceOf: owner } : {}),
        };
      }

      function visitFunction(node: Node, scope: Scope) {
        const name = identifier(field(node, "name"));
        const info = definitions.functions.get(node.startIndex);
        if (name) scope.set(name, { kind: "unknown", origin: "function or class binding", definition: node });
        const child = new Map(scope);
        // A body runs after the module has loaded, so names bound later in the file are visible to it.
        for (const [key, value] of carry.moduleScope) {
          const current = child.get(key);
          if (!current || isNone(current)) child.set(key, value);
        }
        const isMethod = info?.owner !== undefined && !info.decorators.has("staticmethod");
        const inferred = info && carry.parameters.get(info.key);
        (field(node, "parameters")?.namedChildren ?? []).forEach((parameter, position) => {
          const param = identifier(parameter.type === "identifier" ? parameter :
            field(parameter, "name") ?? parameter.firstNamedChild);
          if (!param) return;
          const override = inferred?.get(param);
          const declared = override && parameterBinding(parameter, param, child, info);
          // An annotation that already names the class needs no help from the callers.
          const annotated = declared?.kind === "unknown" && declared.instanceOf !== undefined &&
            override?.kind === "unknown" && declared.instanceOf === override.instanceOf;
          if (override && annotated && declared) child.set(param, declared);
          else if (override?.kind === "literal") child.set(param, { ...override, parameterName: param });
          else if (override) child.set(param, override);
          else if (position === 0 && isMethod && info?.owner) {
            // A member that the class does not define comes from a base class this file may not hold.
            const declaredBases = (field(info.owner, "superclasses")?.namedChildren ?? [])
              .filter((base) => base.type !== "keyword_argument");
            const reach = classBases(info.owner, lookup).length < declaredBases.length ? "external" : "inline";
            child.set(param, info.decorators.has("classmethod")
              ? { kind: "unknown", origin: "function or class binding", definition: info.owner, reach }
              : { kind: "unknown", origin: "untyped function parameter", instanceOf: info.owner, reach });
          } else child.set(param, parameterBinding(parameter, param, child, info));
        });
        const body = field(node, "body");
        const saved = { currentFunction, currentReceiver, declaredGlobals };
        if (currentFunction && info) addEdge(currentFunction.key, info.key);
        currentFunction = info;
        declaredGlobals = new Set();
        if (isMethod) currentReceiver = info?.parameters[0]?.name;
        try {
          if (body) visit(body, child);
        } finally {
          ({ currentFunction, currentReceiver, declaredGlobals } = saved);
        }
        const parameters = field(node, "parameters");
        if (body && name && parameters && node.parent?.type === "module") {
          const params = parameters.namedChildren;
          const statements = body.namedChildren.filter((entry) => entry.type !== "comment");
          const call = statements.length === 1 && statements[0].type === "expression_statement"
            ? statements[0].firstNamedChild : null;
          const target = call?.type === "call" ? field(call, "function") : null;
          const parameter = identifier(field(target, "object"));
          const method = identifier(field(target, "attribute"));
          if (call && parameter && method && params.length === 1 && identifier(params[0]) === parameter) {
            scope.set(name, { kind: "forwarder", parameter, method, call });
          }
        }
        if (name) {
          const wrapper = wrapperFor(node, scope);
          if (wrapper) scope.set(name, { kind: "process-wrapper", wrapper });
        }
        if (name === "__init__") {
          for (const [key, value] of child) {
            if (key.startsWith("self.") && (value.kind === "client" || value.kind === "resource")) scope.set(key, value);
          }
        }
      }

      function visitClass(node: Node, scope: Scope) {
        const name = identifier(field(node, "name"));
        if (name) scope.set(name, { kind: "unknown", origin: "function or class binding", definition: node });
        const body = field(node, "body");
        const saved = { currentFunction, currentClass, currentReceiver };
        currentFunction = undefined;
        currentClass = node;
        currentReceiver = undefined;
        try {
          if (body) visit(body, new Map(scope));
        } finally {
          ({ currentFunction, currentClass, currentReceiver } = saved);
        }
      }

      function visitWith(node: Node, scope: Scope) {
        const previous = mocked;
        const added: Binding[] = [];
        const clause = node.namedChildren.find((item) => item.type === "with_clause");
        if (clause) visit(clause, scope);
        for (const item of clause?.namedChildren ?? []) {
          const value = field(item, "value");
          const expression = value?.type === "as_pattern" ? value.firstNamedChild : value;
          const alias = value?.type === "as_pattern" ? field(value, "alias")?.firstNamedChild ?? null : null;
          if (alias && expression) {
            const entered = resolve(expression, scope, lookup);
            store(alias, entered ?? unknown("unresolved assignment", reachOf(expression, scope, lookup)), scope);
          }
          if (expression?.type !== "call") continue;
          const path = importedPath(expression, scope);
          if (path === "moto.mock_aws") mocked = true;
          if (path === "botocore.stub.Stubber") {
            const receiver = resolve(argumentsOf(expression).args[0] ?? null, scope, lookup);
            if (receiver?.kind === "client" && !stubbed.has(receiver)) {
              stubbed.add(receiver);
              added.push(receiver);
            }
          }
        }
        try {
          const body = field(node, "body");
          if (body) visit(body, scope);
        } finally {
          mocked = previous;
          for (const receiver of added) stubbed.delete(receiver);
        }
      }

      function visitBranches(node: Node, scope: Scope) {
        const alternatives: Scope[] = [];
        if (node.type === "if_statement") {
          for (const item of node.namedChildren) {
            if (!["block", "elif_clause", "else_clause"].includes(item.type)) {
              visit(item, scope);
              continue;
            }
            const branch = new Map(scope);
            visit(item, branch);
            alternatives.push(branch);
          }
        } else {
          const branch = new Map(scope);
          if (node.type === "for_statement") {
            bindLoopTargets(field(node, "left"), branch, reachOf(field(node, "right"), scope, lookup));
          }
          for (const item of node.namedChildren) visit(item, branch);
          alternatives.push(branch);
        }
        const changed = new Set<string>();
        for (const branch of alternatives) {
          for (const [key, value] of branch) if (scope.get(key) !== value) changed.add(key);
        }
        for (const key of changed) {
          const candidates = [scope.get(key), ...alternatives.map((branch) => branch.get(key))]
            .filter((candidate) => candidate !== undefined);
          // A name bound on only some paths keeps that binding: using it on the other paths fails at runtime.
          const merged = agree(candidates);
          if (carriesValue(merged)) scope.set(key, merged);
          else if (candidates.every(isNone)) scope.set(key, candidates[0]);
          else {
            const reach = mergeReach(candidates.filter((value) => !isNone(value)).map(bindingReach));
            scope.set(key, candidates.some((value) => value.kind === "client" || value.kind === "resource")
              ? { kind: "client", reach } : unknown("control-flow merge", reach));
          }
        }
      }

      function visit(node: Node, scope: Scope) {
        if (node.type === "import_statement" || node.type === "import_from_statement") {
          bindImports(node, scope, imports);
          return;
        }
        if (node.type === "decorated_definition") {
          const definition = field(node, "definition");
          const decorators = node.namedChildren.filter((item) => item.type === "decorator");
          const previous = mocked;
          for (const decorator of decorators) visit(decorator, scope);
          mocked ||= decorators.some((item) => importedPath(item.firstNamedChild, scope) === "moto.mock_aws");
          try {
            if (definition) visit(definition, scope);
          } finally {
            mocked = previous;
          }
          return;
        }
        if (node.type === "with_statement") return visitWith(node, scope);
        if (node.type === "function_definition") return visitFunction(node, scope);
        if (node.type === "class_definition") return visitClass(node, scope);
        if (branches.has(node.type)) return visitBranches(node, scope);
        if (comprehensions.has(node.type)) return visitComprehension(node, scope);
        if (node.type === "global_statement") {
          for (const name of node.namedChildren) declaredGlobals.add(name.text);
          return;
        }
        if (node.type === "return_statement" && currentFunction) {
          const value = node.firstNamedChild;
          if (value && value.type !== "none") {
            const result = resolve(value, scope, lookup);
            push(returned, currentFunction.key, result ?? unknown("unresolved assignment", reachOf(value, scope, lookup)));
          }
        }
        if (node.type === "call") inspectCall(node, scope);
        if (node.type === "attribute") {
          const member = field(node, "attribute")?.text;
          const object = field(node, "object");
          if (member === "method_to_api_mapping" && field(object, "attribute")?.text === "meta") {
            const receiver = resolve(field(object, "object"), scope, lookup);
            if (receiver?.kind === "client") {
              emit(node, "method_to_api_mapping", unknownAws("method name is dynamic"), receiver, "inline");
            }
          }
          const parent = node.parent;
          const called = parent?.type === "call" && field(parent, "function")?.id === node.id;
          const assigned = (parent?.type === "assignment" || parent?.type === "augmented_assignment") &&
            field(parent, "left")?.id === node.id;
          if (member && object && !called && !assigned) inspectSdkUse(node, object, member, scope, true);
        }
        for (const child of node.namedChildren) visit(child, scope);
        if (node.type === "assignment" || node.type === "augmented_assignment") assign(node, scope);
      }

      visit(root, moduleScope);

      const parameters = new Map<number, Map<string, Binding>>();
      for (const info of definitions.functions.values()) {
        const recorded = sites.get(info.key);
        if (!recorded?.length || info.escapes || info.forwarder) continue;
        const complete = recorded.filter((site) => site !== undefined);
        if (complete.length !== recorded.length) continue;
        const implicit = info.owner && !info.decorators.has("staticmethod") ? info.parameters[0] : undefined;
        const inferred = new Map<string, Binding>();
        for (const parameter of info.parameters) {
          if (parameter.kind !== "plain" || parameter === implicit) continue;
          // A recursive call that passes the parameter through says nothing new about it.
          const passed = complete.map((site) => site.get(parameter.name)).filter((binding) =>
            !(binding?.kind === "unknown" && binding.parameterOf === info.key && binding.parameterName === parameter.name));
          // Callers that pass None, or nothing for a None default, leave the parameter None on that path.
          const merged = passed.length && passed.every(isNone) ? passed[0] : agree(passed);
          if (merged && (isNone(merged) || carriesValue(merged))) {
            inferred.set(parameter.name, info.private ? merged : withNote(merged, callerNote));
          }
        }
        if (inferred.size) parameters.set(info.key, inferred);
      }
      const returns = new Map<number, Binding>();
      const returnReach = new Map<number, Reach>();
      const called = new Set([...sites].filter(([, recorded]) => recorded.length > 0).map(([key]) => key));
      for (const [key, values] of returned) {
        const merged = agree(values);
        const info = definitions.functions.get(key);
        if (merged && info && (isHandle(merged) || merged.kind === "tuple" ||
            (merged.kind === "unknown" && merged.instanceOf))) returns.set(key, detach(merged, info.parameters));
        else returnReach.set(key, mergeReach(values.filter((value) => !isNone(value)).map(bindingReach)));
      }
      const settledAttributes = new Map<number, Map<string, Binding>>();
      for (const [owner, names] of attributes) {
        settledAttributes.set(owner, new Map([...names].map(([name, values]) => [name, settle(values)])));
      }
      const finalScope = new Map(moduleScope);
      for (const [name, values] of globals) {
        const declared = finalScope.get(name);
        finalScope.set(name, settle(declared ? [declared, ...values] : values));
      }
      return {
        findings, owners, edges, processes: [...processes.values()],
        next: { parameters, returns, attributes: settledAttributes, moduleScope: finalScope, returnReach, called },
      };
    }

    let carry = emptyCarry();
    let round = runRound(carry);
    for (let count = 1; count < maxRounds && carrySignature(round.next) !== carrySignature(carry); count++) {
      carry = round.next;
      round = runRound(carry);
    }
    if (carrySignature(round.next) !== carrySignature(carry)) {
      // The facts did not settle, so report without any cross-function inference.
      carry = emptyCarry();
      round = runRound(carry);
    }

    const located = round.findings.map((finding, index) => ({ finding, owner: round.owners[index] }));
    for (const { owner, run } of round.processes) {
      const finding = await run();
      if (finding) located.push({ finding, owner });
    }
    const findings = located.map(({ finding }) => finding).sort((a, b) => a.line - b.line || a.column - b.column);

    const lookup: Lookup = { catalog, definitions, carry, imports };
    const reachable = (key: number) => {
      const seen = new Set([key]);
      const work = [key];
      while (work.length) {
        for (const next of round.edges.get(work.pop()!) ?? []) {
          if (seen.has(next)) continue;
          seen.add(next);
          work.push(next);
        }
      }
      return seen;
    };
    const summarizeFunction = (info: FunctionInfo): FunctionSummary => {
      const reached = reachable(info.key);
      return {
        parameters: info.parameters, decorators: info.decorators,
        returns: portable(carry.returns.get(info.key) ?? annotatedReturn(info, lookup)),
        effects: located.filter(({ owner }) => owner !== undefined && reached.has(owner)).map(({ finding }) => finding),
      };
    };
    const summarizeClass = (node: Node): ClassSummary => {
      const attributes = new Map<string, Binding>();
      const methods = new Map<string, FunctionSummary>();
      const absorb = (owner: ClassRef, depth: number) => {
        if ("imported" in owner) {
          for (const [name, binding] of owner.attributes) if (!attributes.has(name)) attributes.set(name, binding);
          for (const [name, method] of owner.methods) if (!methods.has(name)) methods.set(name, method);
          return;
        }
        for (const name of carry.attributes.get(owner.startIndex)?.keys() ?? []) {
          const binding = attributes.has(name) ? undefined : portable(classAttribute(node, name, lookup));
          if (binding) attributes.set(name, binding);
        }
        for (const [name, info] of definitions.methods.get(owner.startIndex) ?? []) {
          if (!methods.has(name)) methods.set(name, summarizeFunction(info));
        }
        if (depth < maxClassDepth) for (const base of classBases(owner, lookup)) absorb(base, depth + 1);
      };
      absorb(node, 0);
      return { imported: true, attributes, methods };
    };
    const functions = new Map<string, FunctionSummary>();
    for (const info of definitions.functions.values()) {
      if (info.topLevel) functions.set(info.name, summarizeFunction(info));
    }
    const classes = new Map([...definitions.classes].map(([name, node]) => [name, summarizeClass(node)]));
    const values = new Map<string, Binding>();
    for (const [name, binding] of carry.moduleScope) {
      const kept = portable(binding);
      if (kept) values.set(name, kept);
      // A package that imports a helper and exposes it lets callers import it from the package.
      const reexported = binding.kind === "unknown" ? binding.summary : undefined;
      if (reexported && "imported" in reexported) classes.set(name, reexported);
      else if (reexported) functions.set(name, reexported);
    }
    return { findings, summary: { functions, classes, values } };
  });
}
