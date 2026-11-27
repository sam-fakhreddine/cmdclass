import type { Node } from "web-tree-sitter";
import { resourceShape } from "../aws/resources.ts";
import type { loadResources } from "../aws/resources.ts";
import type { Finding } from "../report.ts";
import { callArguments, mapArguments } from "./definitions.ts";
import type { Definitions, FunctionInfo, Parameter } from "./definitions.ts";

export type Catalog = Awaited<ReturnType<typeof loadResources>>;
export type UnknownOrigin =
  | "untracked import"
  | "function or class binding"
  | "untyped function parameter"
  | "unsupported parameter annotation"
  | "unresolved assignment"
  | "control-flow merge"
  | "unresolved name"
  | "unresolved attribute"
  | "unresolved call result"
  | "unresolved expression";
/** Whether an untraceable value is decided outside this file or computed inside it. */
export type Reach = "external" | "inline";
export interface ProcessWrapper {
  parameters: string[];
  rest: string;
  command: Node;
  process: Node;
}

/** What an imported function does, in a form that outlives the imported module's syntax tree. */
export interface FunctionSummary {
  parameters: readonly Parameter[];
  decorators: ReadonlySet<string>;
  returns?: Binding;
  /** AWS findings reached when the function runs; reported again at each call site. */
  effects: readonly Finding[];
}
export interface ClassSummary {
  imported: true;
  attributes: ReadonlyMap<string, Binding>;
  methods: ReadonlyMap<string, FunctionSummary>;
}
export interface ModuleSummary {
  functions: ReadonlyMap<string, FunctionSummary>;
  classes: ReadonlyMap<string, ClassSummary>;
  values: ReadonlyMap<string, Binding>;
}
/** A class defined in this file (its syntax node) or imported from another one (its summary). */
export type ClassRef = Node | ClassSummary;
const isClassSummary = (value: object): value is ClassSummary => "imported" in value;

export interface Handle {
  kind: "session" | "client" | "resource";
  service?: string;
  /** The service is the argument passed for this parameter of the function that returned the handle. */
  serviceParameter?: string;
  context?: Record<string, string>;
  shape?: string;
  collection?: boolean;
  /** Provenance caveat appended to the reason of findings on this handle. */
  note?: string;
  /** Caveat about how the service alone was determined; dropped once a call supplies the service itself. */
  serviceNote?: string;
  /** Where the missing service of a handle without one comes from. */
  reach?: Reach;
}
export type Binding =
  | { kind: "module"; path: string }
  | { kind: "literal"; value: string; note?: string; parameterName?: string }
  | Handle
  | { kind: "tuple"; items: (Binding | undefined)[] }
  /** A value an SDK client returned (response, paginator, waiter): known not to be a client. */
  | { kind: "response" }
  | { kind: "process-wrapper"; wrapper: ProcessWrapper }
  | { kind: "forwarder"; parameter: string; method: string; call: Node }
  | {
    kind: "unknown";
    origin?: UnknownOrigin;
    /** The function or class definition this name is bound to. */
    definition?: Node;
    /** The imported function or class this name is bound to. */
    summary?: FunctionSummary | ClassSummary;
    instanceOf?: ClassRef;
    /** Set on a parameter that has no better binding: the owning function and the parameter name. */
    parameterOf?: number;
    parameterName?: string;
    /** Assigned None; ignored when merging with real values. */
    none?: boolean;
    note?: string;
    /** The value came from `.client("service")` on a receiver that could not be traced to a session. */
    candidateService?: string;
    reach?: Reach;
  };
export type Scope = Map<string, Binding>;

/** Facts carried from one analysis round to the next until they stop changing. */
export interface Carry {
  parameters: ReadonlyMap<number, ReadonlyMap<string, Binding>>;
  returns: ReadonlyMap<number, Binding>;
  attributes: ReadonlyMap<number, ReadonlyMap<string, Binding>>;
  moduleScope: ReadonlyMap<string, Binding>;
  /** Reach of the value returned by functions whose return could not be traced. */
  returnReach: ReadonlyMap<number, Reach>;
  /** Functions with at least one call site in this file. */
  called: ReadonlySet<number>;
}
export interface Lookup {
  catalog: Catalog;
  definitions: Definitions;
  carry: Carry;
  imports: ReadonlyMap<string, ModuleSummary>;
  /** Results of the resolution in progress, by node id. */
  memo?: Map<number, Binding | undefined>;
}
export interface Callee {
  info?: FunctionInfo;
  summary?: FunctionSummary;
  /** The first declared parameter is the implicit receiver. */
  bound: boolean;
  constructs?: ClassRef;
  /** The receiver could not be traced: any of these methods may be the target. */
  ambiguous?: readonly FunctionInfo[];
}

const externalOrigins: ReadonlySet<UnknownOrigin> = new Set([
  "untracked import", "untyped function parameter", "unsupported parameter annotation", "unresolved name",
]);
// Names Python always provides: a call to one is computed here, not handed in from outside.
const builtinNames = new Set([
  "abs", "all", "any", "bool", "bytes", "dict", "enumerate", "filter", "float", "format", "frozenset", "getattr",
  "id", "int", "isinstance", "iter", "len", "list", "map", "max", "min", "next", "object", "open", "print", "range",
  "repr", "reversed", "round", "set", "sorted", "str", "sum", "super", "tuple", "type", "vars", "zip",
]);
const maxReachDepth = 32;
export const unknown = (origin: UnknownOrigin, reach?: Reach): Binding =>
  ({ kind: "unknown", origin, reach: reach ?? (externalOrigins.has(origin) ? "external" : "inline") });
export const mergeReach = (reaches: readonly (Reach | undefined)[]): Reach =>
  reaches.includes("external") ? "external" : "inline";
export const field = (node: Node | null, name: string) => node?.childForFieldName(name) ?? null;
export const identifier = (node: Node | null) => node?.type === "identifier" ? node.text : undefined;
export const safeName = (value: string | undefined) => value && /^[a-zA-Z0-9._-]+$/.test(value) ? value : undefined;
export const simpleString = (node: Node | null) => {
  if (node?.type !== "string") return undefined;
  return /^(["'])([^"'\\\r\n]*)\1$/.exec(node.text)?.[2];
};
export const isHandle = (binding: Binding | undefined): binding is Handle =>
  binding?.kind === "client" || binding?.kind === "resource" || binding?.kind === "session";
export const awsModule = /^(?:boto3|aioboto3|botocore|moto)(?:\.|$)/;
export const trackedModule = /^(?:boto3|aioboto3|botocore|moto|subprocess|asyncio|os|pty)(?:\.|$)/;
export const sessionTypePaths = new Set([
  "boto3.Session", "boto3.session.Session", "aioboto3.Session", "aioboto3.session.Session",
]);
const sessionFactoryPaths = new Set([...sessionTypePaths, "botocore.session.get_session"]);
const maxClassDepth = 5;

export function argumentsOf(call: Node) {
  const args = field(call, "arguments")?.namedChildren ?? [];
  const keyword = (key: string) => field(args.find((arg) =>
    arg.type === "keyword_argument" && field(arg, "name")?.text === key) ?? null, "value");
  return { args, keyword, unpacked: args.some((n) => n.type === "dictionary_splat") };
}

export function literal(node: Node | null, scope: Scope) {
  const v = node && scope.get(node.text);
  return v?.kind === "literal" ? v.value : simpleString(node);
}

function policyContext(call: Node, scope: Scope, previous?: Record<string, string>) {
  const { keyword } = argumentsOf(call);
  const context = { ...previous };
  for (const [argument, label] of [["profile_name", "profile"], ["region_name", "region"]]) {
    const node = keyword(argument);
    if (!node) continue;
    const value = safeName(literal(node, scope));
    if (value) context[label] = value;
    else delete context[label];
  }
  return Object.keys(context).length ? context : undefined;
}

/** Identity of a binding for comparing analysis rounds and call sites. */
export function signature(binding: Binding | undefined): string {
  if (!binding) return "-";
  switch (binding.kind) {
    case "module": return `module:${binding.path}`;
    case "literal": return `literal:${binding.value}`;
    case "tuple": return `tuple(${binding.items.map(signature).join(",")})`;
    case "response": return "response";
    case "process-wrapper": return `wrapper:${binding.wrapper.process.startIndex}`;
    case "forwarder": return `forwarder:${binding.call.startIndex}`;
    case "unknown": {
      const instance = binding.instanceOf && !isClassSummary(binding.instanceOf) ? binding.instanceOf.startIndex : "";
      const imported = binding.instanceOf && isClassSummary(binding.instanceOf) ? "imported" : "";
      return `unknown:${binding.origin ?? ""}:${binding.definition?.startIndex ?? ""}:${instance}${imported}:${
        binding.summary ? "summary" : ""}:${binding.none ? "none" : ""}:${binding.candidateService ?? ""}:${
        binding.reach ?? ""}`;
    }
    default:
      return JSON.stringify([binding.kind, binding.service, binding.serviceParameter, binding.shape,
        binding.collection, Object.entries(binding.context ?? {}).sort(), binding.note, binding.serviceNote,
        binding.reach]);
  }
}

/**
 * The single binding that every candidate agrees on, or undefined when they differ.
 * Handles that differ only in profile or region keep the service and drop the context.
 */
export function unify(first: Binding | undefined, second: Binding | undefined): Binding | undefined {
  if (!first || !second) return undefined;
  if (isHandle(first) && isHandle(second)) {
    if (first.kind !== second.kind || first.service !== second.service ||
        first.serviceParameter !== second.serviceParameter || first.shape !== second.shape ||
        first.serviceNote !== second.serviceNote ||
        first.collection !== second.collection) return undefined;
    const sameContext = signature({ kind: "session", context: first.context }) ===
      signature({ kind: "session", context: second.context });
    const note = first.note ?? second.note;
    const reach = first.reach || second.reach ? mergeReach([first.reach, second.reach]) : undefined;
    return {
      ...first, context: sameContext ? first.context : undefined, ...(note ? { note } : {}), ...(reach ? { reach } : {}),
    };
  }
  if (first.kind === "tuple" && second.kind === "tuple") {
    if (first.items.length !== second.items.length) return undefined;
    return { kind: "tuple", items: first.items.map((item, index) => unify(item, second.items[index])) };
  }
  return signature(first) === signature(second) ? first : undefined;
}

export const isNone = (binding: Binding | undefined) => binding?.kind === "unknown" && binding.none === true;

/** Folds every binding a name can hold into one; None is ignored because a call on None fails anyway. */
export function agree(candidates: readonly (Binding | undefined)[]): Binding | undefined {
  const real = candidates.filter((candidate) => !isNone(candidate));
  if (!real.length) return undefined;
  let merged = real[0];
  for (const candidate of real.slice(1)) merged = unify(merged, candidate);
  return merged;
}

function importedMember(imports: Lookup["imports"], module: string, name: string): Binding | undefined {
  const summary = imports.get(module);
  if (!summary) return undefined;
  const callable = summary.functions.get(name) ?? summary.classes.get(name);
  if (callable) return { kind: "unknown", origin: "untracked import", summary: callable, reach: "external" };
  return summary.values.get(name);
}

export function classBases(owner: Node, lookup: Lookup): ClassRef[] {
  const bases: ClassRef[] = [];
  for (const base of field(owner, "superclasses")?.namedChildren ?? []) {
    if (base.type === "keyword_argument") continue;
    const binding = resolve(base, lookup.carry.moduleScope as Scope, lookup);
    if (binding?.kind !== "unknown") continue;
    if (binding.definition?.type === "class_definition") bases.push(binding.definition);
    else if (binding.summary && isClassSummary(binding.summary)) bases.push(binding.summary);
  }
  return bases;
}

export function findMethod(
  owner: ClassRef, name: string, lookup: Lookup, depth = 0,
): Pick<Callee, "info" | "summary"> | undefined {
  if (isClassSummary(owner)) {
    const summary = owner.methods.get(name);
    return summary && { summary };
  }
  const info = lookup.definitions.methods.get(owner.startIndex)?.get(name);
  if (info) return { info };
  if (depth >= maxClassDepth) return undefined;
  for (const base of classBases(owner, lookup)) {
    const inherited = findMethod(base, name, lookup, depth + 1);
    if (inherited) return inherited;
  }
  return undefined;
}

export function classAttribute(owner: ClassRef, name: string, lookup: Lookup, depth = 0): Binding | undefined {
  if (isClassSummary(owner)) {
    const stored = owner.attributes.get(name);
    if (stored) return stored;
    const accessor = owner.methods.get(name);
    return accessor?.decorators.has("property") ? accessor.returns : undefined;
  }
  const stored = lookup.carry.attributes.get(owner.startIndex)?.get(name);
  if (stored && !(stored.kind === "unknown" && !stored.instanceOf)) return stored;
  const accessor = lookup.definitions.methods.get(owner.startIndex)?.get(name);
  if (accessor?.decorators.has("property")) return lookup.carry.returns.get(accessor.key);
  if (depth < maxClassDepth) {
    for (const base of classBases(owner, lookup)) {
      const inherited = classAttribute(base, name, lookup, depth + 1);
      if (inherited) return inherited;
    }
  }
  return stored;
}

export function bindingReach(binding: Binding): Reach {
  if (binding.kind === "unknown") {
    return binding.reach ?? (binding.origin && externalOrigins.has(binding.origin) ? "external" : "inline");
  }
  if (binding.kind === "module") return trackedModule.test(binding.path) ? "inline" : "external";
  return isHandle(binding) && binding.reach ? binding.reach : "inline";
}

/** Where the value of an expression that could not be traced comes from. */
export function reachOf(node: Node | null, scope: Scope, lookup: Lookup, depth = 0): Reach {
  if (!node || depth > maxReachDepth) return "inline";
  const bound = resolve(node, scope, lookup);
  if (bound) return bindingReach(bound);
  if (node.type === "identifier") return builtinNames.has(node.text) ? "inline" : "external";
  if (node.type === "attribute") return reachOf(field(node, "object"), scope, lookup, depth + 1);
  if (node.type === "subscript") return reachOf(field(node, "value"), scope, lookup, depth + 1);
  if (node.type === "call") {
    const callee = calleeOf(node, scope, lookup);
    if (callee?.info) return lookup.carry.returnReach.get(callee.info.key) ?? "inline";
    if (callee?.summary) return "external";
    return reachOf(field(node, "function"), scope, lookup, depth + 1);
  }
  return mergeReach(node.namedChildren.map((child) => reachOf(child, scope, lookup, depth + 1)));
}

/** The class a name is bound to, when it names a class defined here or imported. */
export function classOf(binding: Binding | undefined): ClassRef | undefined {
  if (binding?.kind !== "unknown") return undefined;
  if (binding.definition?.type === "class_definition") return binding.definition;
  return binding.summary && isClassSummary(binding.summary) ? binding.summary : undefined;
}

/** Carries a provenance caveat from the value a handle was derived from. */
function tagged(result: Binding | undefined, source: Binding | undefined): Binding | undefined {
  const note = source && "note" in source ? source.note : undefined;
  return note && isHandle(result) && !result.note ? { ...result, note } : result;
}

export function calleeOf(call: Node, scope: Scope, lookup: Lookup): Callee | undefined {
  return calleeFor(field(call, "function"), scope, lookup);
}

/** The function an expression refers to, whether it is being called or passed along to be called. */
export function calleeFor(fn: Node | null, scope: Scope, lookup: Lookup): Callee | undefined {
  if (!fn) return undefined;
  const target = resolve(fn, scope, lookup);
  const constructed = classOf(target);
  if (constructed) return { ...findMethod(constructed, "__init__", lookup), bound: true, constructs: constructed };
  if (target?.kind === "unknown" && target.definition) {
    const info = lookup.definitions.functions.get(target.definition.startIndex);
    return info && { info, bound: false };
  }
  if (target?.kind === "unknown" && target.summary && !isClassSummary(target.summary)) {
    return { summary: target.summary, bound: false };
  }
  if (fn.type !== "attribute") return undefined;
  const name = field(fn, "attribute")?.text;
  if (!name) return undefined;
  const receiver = resolve(field(fn, "object"), scope, lookup);
  if (receiver && receiver.kind !== "unknown") return undefined;
  if (receiver?.instanceOf) {
    const method = findMethod(receiver.instanceOf, name, lookup);
    const decorators = method?.info?.decorators ?? method?.summary?.decorators;
    return method && { ...method, bound: !decorators?.has("staticmethod") };
  }
  const owner = classOf(receiver);
  if (owner) {
    const method = findMethod(owner, name, lookup);
    const decorators = method?.info?.decorators ?? method?.summary?.decorators;
    if (!method || !decorators) return undefined;
    if (decorators.has("staticmethod")) return { ...method, bound: false };
    return decorators.has("classmethod") ? { ...method, bound: true } : undefined;
  }
  const candidates = name.startsWith("__") ? undefined : lookup.definitions.methodsByName.get(name);
  return candidates && { bound: true, ambiguous: candidates };
}

/** The handle a function is annotated to return, for functions whose body does not settle it. */
export function annotatedReturn(info: FunctionInfo, lookup: Lookup): Binding | undefined {
  const type = field(info.node, "return_type");
  const annotation = resolve(type?.firstNamedChild ?? null, lookup.carry.moduleScope as Scope, lookup);
  return annotation?.kind === "module" && sessionTypePaths.has(annotation.path) ? { kind: "session" } : undefined;
}

/** Replaces a handle's service parameter with the argument this call passes for it. */
function specialize(binding: Binding, call: Node, callee: Callee, scope: Scope, lookup: Lookup): Binding {
  if (binding.kind === "tuple") {
    return { kind: "tuple", items: binding.items.map((item) => item && specialize(item, call, callee, scope, lookup)) };
  }
  if (!isHandle(binding) || !binding.serviceParameter) return binding;
  const { serviceParameter, serviceNote: _fromInference, ...settled } = binding;
  const { service: _inferred, ...rest } = settled;
  const declared = callee.info?.parameters ?? callee.summary?.parameters ?? [];
  const argument = mapArguments(callArguments(call), declared, callee.bound)?.get(serviceParameter);
  if (!argument) return binding.service ? { ...settled, serviceNote: binding.serviceNote } : rest;
  const service = safeName(literal(argument, scope));
  const { reach: _unspecialized, ...known } = rest;
  if (service) return { ...known, service };
  const source = scope.get(argument.text);
  const passed = source?.kind === "unknown" && source.parameterName ? { serviceParameter: source.parameterName } : {};
  return { ...known, ...passed, reach: reachOf(argument, scope, lookup) };
}

/**
 * The binding an expression evaluates to, or undefined when it cannot be traced.
 * One resolution reads the receiver of a chained expression several times per link, so results
 * are remembered until the outermost call returns; the scope does not change in between.
 */
export function resolve(node: Node | null, scope: Scope, lookup: Lookup): Binding | undefined {
  if (!node) return undefined;
  if (lookup.memo) {
    if (lookup.memo.has(node.id)) return lookup.memo.get(node.id);
    const result = resolveNode(node, scope, lookup);
    lookup.memo.set(node.id, result);
    return result;
  }
  lookup.memo = new Map();
  try {
    return resolve(node, scope, lookup);
  } finally {
    lookup.memo = undefined;
  }
}

function resolveNode(node: Node, scope: Scope, lookup: Lookup): Binding | undefined {
  if (node.type === "identifier") return scope.get(node.text);
  if (node.type === "await" || node.type === "parenthesized_expression") return resolve(node.firstNamedChild, scope, lookup);
  if (node.type === "tuple" || node.type === "expression_list") {
    const items = node.namedChildren.map((item) => resolve(item, scope, lookup));
    return items.some(isHandle) ? { kind: "tuple", items } : undefined;
  }
  if (node.type === "boolean_operator" && field(node, "operator")?.type === "or") {
    // `injected or default`: the default when the injected value is None, otherwise either one.
    const injected = resolve(field(node, "left"), scope, lookup);
    const fallback = resolve(field(node, "right"), scope, lookup);
    return isNone(injected) ? tagged(fallback, injected) : unify(injected, fallback);
  }
  if (node.type === "conditional_expression") {
    const [first, , second] = node.namedChildren;
    const choices = [resolve(first ?? null, scope, lookup), resolve(second ?? null, scope, lookup)];
    return choices.every((choice) => choice !== undefined) ? agree(choices) : undefined;
  }
  if (node.type === "subscript") {
    const bound = scope.get(node.text);
    if (bound) return bound;
    const value = resolve(field(node, "value"), scope, lookup);
    const index = field(node, "subscript");
    return value?.kind === "tuple" && index?.type === "integer" ? value.items[Number(index.text)] : undefined;
  }
  if (node.type === "attribute") {
    const bound = scope.get(node.text);
    if (bound) return bound;
    const base = resolve(field(node, "object"), scope, lookup);
    const attr = field(node, "attribute")?.text;
    if (base?.kind === "module" && attr) {
      return importedMember(lookup.imports, base.path, attr) ?? { kind: "module", path: `${base.path}.${attr}` };
    }
    if (base?.kind === "resource" && attr && !base.collection) {
      const collections = resourceShape(lookup.catalog, base.service, base.shape)?.collections;
      if (collections && Object.hasOwn(collections, attr)) return { ...base, shape: collections[attr], collection: true };
    }
    if (base?.kind === "unknown" && base.instanceOf && attr) {
      return tagged(classAttribute(base.instanceOf, attr, lookup), base);
    }
    return undefined;
  }
  if (node.type !== "call") return undefined;
  const fn = field(node, "function");
  const object = resolve(field(fn, "object"), scope, lookup);
  const method = field(fn, "attribute")?.text;
  const target = fn?.type === "attribute"
    ? object?.kind === "module" && method ? { kind: "module" as const, path: `${object.path}.${method}` } : undefined
    : resolve(fn, scope, lookup);
  const { args, keyword } = argumentsOf(node);
  if (target?.kind === "module" && sessionFactoryPaths.has(target.path)) {
    return { kind: "session", context: policyContext(node, scope) };
  }
  const direct = target?.kind === "module" && /^(?:boto3|aioboto3)\.(?:client|resource)$/.test(target.path);
  if (direct || (object?.kind === "session" && ["client", "resource", "create_client"].includes(method ?? ""))) {
    const serviceNode = keyword("service_name") ?? args[0] ?? null;
    const service = safeName(literal(serviceNode, scope));
    const named = serviceNode ? scope.get(serviceNode.text) : undefined;
    const session = object?.kind === "session" ? object : undefined;
    const fromParameter = named?.kind === "literal" || named?.kind === "unknown" ? named.parameterName : undefined;
    const serviceNote = named?.kind === "literal" ? named.note : undefined;
    return {
      kind: (method ?? (target?.kind === "module" ? target.path.split(".").at(-1) : "")) === "resource"
        ? "resource" : "client",
      service,
      ...(fromParameter ? { serviceParameter: fromParameter } : {}),
      context: policyContext(node, scope, session?.context),
      ...(session?.note ? { note: session.note } : {}),
      ...(serviceNote ? { serviceNote } : {}),
      ...(service ? {} : { reach: reachOf(serviceNode, scope, lookup) }),
    };
  }
  if (object?.kind === "resource" && method) {
    const shape = resourceShape(lookup.catalog, object.service, object.shape);
    if (object.collection && ["all", "filter", "limit", "page_size"].includes(method)) return object;
    if (shape && !object.collection) {
      const type = Object.hasOwn(shape.constructors, method) ? shape.constructors[method] :
        Object.hasOwn(shape.actions, method) ? shape.actions[method].result : undefined;
      if (type) return { ...object, shape: type };
    }
  }
  if ((object?.kind === "client" || object?.kind === "response") && method) return { kind: "response" };
  if ((method === "client" || method === "resource") && (!object || object.kind === "unknown")) {
    const candidateService = safeName(literal(keyword("service_name") ?? args[0] ?? null, scope));
    const reach = object ? bindingReach(object) : reachOf(field(fn, "object"), scope, lookup);
    if (candidateService) return { kind: "unknown", origin: "unresolved assignment", candidateService, reach };
  }
  const callee = calleeOf(node, scope, lookup);
  if (!callee) return undefined;
  if (callee.constructs) {
    const reach = isClassSummary(callee.constructs) ? "external" : "inline";
    return { kind: "unknown", origin: "unresolved assignment", instanceOf: callee.constructs, reach };
  }
  const returned = callee.info
    ? lookup.carry.returns.get(callee.info.key) ?? annotatedReturn(callee.info, lookup)
    : callee.summary?.returns;
  return returned && tagged(specialize(returned, node, callee, scope, lookup), object);
}

export function bindImports(node: Node, scope: Scope, imports: Lookup["imports"]) {
  const from = field(node, "module_name")?.text;
  const summary = from === undefined ? undefined : imports.get(from);
  if (summary && node.namedChildren.some((child) => child.type === "wildcard_import")) {
    for (const name of [...summary.functions.keys(), ...summary.classes.keys(), ...summary.values.keys()]) {
      const member = importedMember(imports, from!, name);
      if (member) scope.set(name, member);
    }
    return;
  }
  for (const name of node.childrenForFieldName("name")) {
    const qualified = (field(name, "name") ?? name).text;
    const alias = field(name, "alias")?.text ?? (from ? qualified : qualified.split(".")[0]);
    const path = from ? `${from}${from.endsWith(".") ? "" : "."}${qualified}` : field(name, "alias") ? qualified : alias;
    const member = from === undefined ? undefined : importedMember(imports, from, qualified);
    if (member) {
      scope.set(alias, member);
      continue;
    }
    const projectModule = [...imports.keys()].some((key) => key === path || key.startsWith(`${path}.`));
    scope.set(alias, trackedModule.test(path) || projectModule ? { kind: "module", path } : unknown("untracked import"));
  }
}
