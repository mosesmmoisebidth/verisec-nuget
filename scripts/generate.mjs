#!/usr/bin/env node
// Generates the typed surface of the .NET SDK from the spec (../spec/openapi.json, the JSON twin of openapi.yaml):
//
//   src/VeriSec/Generated/Models.g.cs       one type per component schema: a class per object schema (request types
//                                           take Image / FileInput where the spec has images and files; answers
//                                           derive from ApiResult, the open "major" answers from OpenResult), string
//                                           constants for the string schemas, a dictionary type for map schemas, the
//                                           nested inline types (<Parent><Property>, list items singular), and the
//                                           query parameter types of the GET operations (x-params-type)
//   src/VeriSec/Generated/Resources.g.cs    one resource class per operationId prefix (client.Face, client.Phone.Otp)
//                                           and one async method per operation, with its summary, the first
//                                           paragraph of its description and its price
//   tests/VeriSec.Tests/Integration/EveryOperationTests.g.cs
//                                           one integration test per operation, built from its spec example
//
// Re-run after the spec changes (from dotnet/):   node scripts/generate.mjs
// Needs Node 18 or later and nothing else.

import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DOTNET = path.resolve(HERE, '..');
const SPEC_PATH = path.resolve(DOTNET, '..', 'spec', 'openapi.json');
const MODELS = path.join(DOTNET, 'src', 'VeriSec', 'Generated', 'Models.g.cs');
const RESOURCES = path.join(DOTNET, 'src', 'VeriSec', 'Generated', 'Resources.g.cs');
const TESTS = path.join(DOTNET, 'tests', 'VeriSec.Tests', 'Integration', 'EveryOperationTests.g.cs');

const spec = JSON.parse(fs.readFileSync(SPEC_PATH, 'utf8'));
const S = spec.components.schemas;

/** Public types written by hand in src/VeriSec: a schema may not take their names. */
const HAND_WRITTEN = new Set([
  'Image', 'FileInput', 'ApiResult', 'OpenResult', 'ResponseInfo', 'RequestOptions', 'VeriSecClient', 'VeriSecOptions',
  'Webhooks', 'WebhookEvent', 'VeriSecException', 'ApiException', 'InvalidRequestException', 'AuthenticationException',
  'InsufficientCreditsException', 'PermissionException', 'NotFoundException', 'RateLimitException', 'ApiServerException',
  'ApiConnectionException', 'ApiTimeoutException', 'SignatureVerificationException',
]);
/** Members a generated property may not take (inherited, or added by the generator). */
const RESERVED_MEMBERS = new Set(['LastResponse', 'AdditionalProperties', 'ToString', 'GetType', 'Equals', 'GetHashCode', 'MemberwiseClone', 'Finalize']);
const CS_KEYWORDS = new Set(('abstract as base bool break byte case catch char checked class const continue decimal default delegate do double else ' +
  'enum event explicit extern false finally fixed float for foreach goto if implicit in int interface internal is lock long namespace new null ' +
  'object operator out override params private protected public readonly ref return sbyte sealed short sizeof stackalloc static string struct ' +
  'switch this throw true try typeof uint ulong unchecked unsafe ushort using virtual void volatile while').split(' '));

// ------------------------------------------------------------------------------------------------ names and docs

const pascal = (text) =>
  String(text)
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((part) => part[0].toUpperCase() + part.slice(1))
    .join('');
const ident = (text) => {
  const name = pascal(text);
  return !name ? '_' : /^[0-9]/.test(name) ? `_${name}` : name;
};
const camel = (text) => {
  const name = ident(text);
  const lower = name[0].toLowerCase() + name.slice(1);
  return CS_KEYWORDS.has(lower) ? `@${lower}` : lower;
};
function singular(word) {
  if (/ies$/.test(word)) return `${word.slice(0, -3)}y`;
  if (/(x|ch|sh|ss|z)es$/.test(word)) return word.slice(0, -2);
  if (/s$/.test(word) && !/ss$/.test(word)) return word.slice(0, -1);
  return word;
}
const refName = (ref) => ref.split('/').pop();
const csString = (value) => JSON.stringify(String(value));
const xml = (text) => String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/** Spec prose (a little Markdown) to XML doc text on one line. */
function prose(text) {
  return xml(String(text).trim())
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/`([^`]+)`/g, '<c>$1</c>')
    .replace(/\s*\n\s*/g, ' ');
}
const sentence = (text) => {
  const t = prose(text);
  return !t || /[.!?:)]$/.test(t) || t.endsWith('</c>') ? t : `${t}.`;
};
const code = (value) => `<c>${xml(typeof value === 'string' && value !== '' ? value : JSON.stringify(value))}</c>`;

/** A <summary> (and more tags) from paragraphs of XML doc text. */
function docBlock(paragraphs, indent, extra = []) {
  const parts = paragraphs.filter(Boolean);
  let out;
  if (parts.length === 1 && parts[0].length < 110) out = `${indent}/// <summary>${parts[0]}</summary>\n`;
  else out = `${indent}/// <summary>\n${parts.map((p, i) => `${indent}/// ${i === 0 ? p : `<para>${p}</para>`}`).join('\n')}\n${indent}/// </summary>\n`;
  for (const line of extra) out += `${indent}/// ${line}\n`;
  return out;
}

// ------------------------------------------------------------------------------------------------ the spec

const resolve = (ref) => ref.replace(/^#\//, '').split('/').reduce((node, key) => node?.[key], spec);
const deref = (node) => (node?.$ref ? deref(resolve(node.$ref)) : node);
const typesOf = (x) => [].concat(x?.type ?? (x?.properties ? 'object' : []));
const isAnySchema = (x) => !x || Object.keys(x).filter((k) => !k.startsWith('x-') && !['description', 'default', 'example', 'examples', 'title'].includes(k)).length === 0;
const isStringSchema = (x) => !!x && !x.$ref && typesOf(x).length === 1 && typesOf(x)[0] === 'string' && x.format !== 'binary';
const hasProperties = (x) => !!x && Object.keys(x.properties ?? {}).length > 0;
const isMapSchema = (x) => !!x && typesOf(x).includes('object') && !hasProperties(x);

const operations = [];
for (const [route, item] of Object.entries(spec.paths)) {
  for (const [verb, op] of Object.entries(item)) {
    if (!op?.operationId) continue;
    const params = [...(item.parameters ?? []), ...(op.parameters ?? [])].map(deref);
    const content = op.requestBody?.content ?? {};
    const json = content['application/json'];
    const form = content['multipart/form-data'];
    const okSchema = op.responses?.['200']?.content?.['application/json']?.schema;
    const envelope = op['x-verisec-envelope'] ?? 'object';
    if (!okSchema?.$ref) throw new Error(`${op.operationId}: the 200 answer must be a $ref`);
    const answer = envelope === 'data' ? refName(deref(okSchema).properties.data.$ref) : refName(okSchema.$ref);
    const segs = op.operationId.split('.');
    operations.push({
      route, verb, op, id: op.operationId, segs: segs.slice(0, -1), method: segs.at(-1), envelope, answer,
      envelopeSchema: envelope === 'data' ? refName(okSchema.$ref) : null,
      json, form, pathParams: params.filter((p) => p.in === 'path'), queryParams: params.filter((p) => p.in === 'query'),
      sdkSource: params.some((p) => p.in === 'header' && p.name.toLowerCase() === 'x-verisec-source'),
      paramsType: json ? refName(json.schema.$ref) : form ? refName(form.schema.$ref) : op['x-params-type'],
    });
  }
}

/** Every schema a request can carry: these become request types (settable, Image/FileInput, required members). */
const requestSchemas = new Set();
function refsIn(node, out) {
  if (Array.isArray(node)) node.forEach((n) => refsIn(n, out));
  else if (node && typeof node === 'object') {
    if (typeof node.$ref === 'string' && node.$ref.startsWith('#/components/schemas/')) {
      const name = refName(node.$ref);
      if (!out.has(name)) {
        out.add(name);
        refsIn(S[name], out);
      }
    }
    for (const [key, value] of Object.entries(node)) if (key !== '$ref' && key !== 'example' && key !== 'examples') refsIn(value, out);
  }
}
for (const o of operations) refsIn(o.op.requestBody, requestSchemas);

const answerRoots = new Set(operations.map((o) => o.answer)); // derive from ApiResult
const openTypes = new Set(operations.filter((o) => o.op['x-verisec-tier'] === 'major').map((o) => o.answer));
for (const name of openTypes) {
  if (hasProperties(S[name]) || S[name].additionalProperties !== true) throw new Error(`${name}: an open (major) answer must be a schema-less object`);
}
const opOfParams = new Map(operations.filter((o) => o.paramsType).map((o) => [o.paramsType, o]));
const opOfEnvelope = new Map(operations.filter((o) => o.envelopeSchema).map((o) => [o.envelopeSchema, o]));

// ------------------------------------------------------------------------------------------------ the type model

/** name -> {name, side, doc, props, root, open, map, entry} in the order they are defined (parents before children). */
const classes = new Map();
/** String schemas: constants classes. */
const constants = [];
/** Map schemas: dictionary types. */
const maps = [];

const takenNames = () => new Set([...classes.keys(), ...Object.keys(S), ...HAND_WRITTEN]);

/**
 * The C# type of a schema, registering nested classes on the way.
 * {cs, kind: scalar|image|file|any|list|map|class, value (a value type), nullable (the schema allows null), item}
 */
function typeOf(x, ctx) {
  const request = ctx.side === 'request';
  if (x?.$ref) {
    const name = refName(x.$ref);
    const target = S[name];
    if (isStringSchema(target)) return {cs: 'string', kind: 'scalar', value: false, nullable: false, constants: target.enum ? name : null, schema: target};
    if (openTypes.has(name) || hasProperties(target) || isMapSchema(target)) return {cs: name, kind: 'class', value: false, nullable: false, schema: target};
    return typeOf(target, ctx);
  }
  if (isAnySchema(x) && !x?.['x-verisec-image']) return anyType(request, false, x);
  if (x['x-verisec-image']) return {cs: 'Image', kind: 'image', value: false, nullable: false, schema: x};
  const variants = x.oneOf ?? x.anyOf;
  if (variants) {
    const real = variants.filter((v) => !(typesOf(v).length === 1 && typesOf(v)[0] === 'null'));
    const nullable = real.length < variants.length;
    if (real.length === 1) return {...typeOf(real[0], ctx), nullable};
    return anyType(request, nullable, x);
  }
  const all = typesOf(x);
  const nullable = all.includes('null');
  const types = all.filter((t) => t !== 'null');
  if (types.length === 0 && x.enum) {
    // an enum without a type: one C# type when the values agree, else any
    const kinds = new Set(x.enum.filter((v) => v !== null).map((v) => (Number.isInteger(v) ? 'integer' : typeof v)));
    if (kinds.size === 1) return typeOf({...x, type: [...kinds][0] === 'string' ? 'string' : [...kinds][0] === 'integer' ? 'integer' : [...kinds][0] === 'boolean' ? 'boolean' : 'number'}, ctx);
    return anyType(request, nullable, x);
  }
  if (types.length !== 1) return anyType(request, nullable, x);
  switch (types[0]) {
    case 'string':
      if (x.format === 'binary') return {cs: 'FileInput', kind: 'file', value: false, nullable: false, schema: x};
      return {cs: 'string', kind: 'scalar', value: false, nullable, schema: x};
    case 'integer':
      return {cs: request ? 'int' : 'long', kind: 'scalar', value: true, nullable, schema: x};
    case 'number':
      return {cs: 'double', kind: 'scalar', value: true, nullable, schema: x};
    case 'boolean':
      return {cs: 'bool', kind: 'scalar', value: true, nullable, schema: x};
    case 'array': {
      const list = x['x-verisec-image-list'];
      const item = typeOf(x.items ?? {}, {...ctx, item: true, imageEntry: list?.imageKey ? list : null});
      return {cs: `IReadOnlyList<${itemDecl(item)}>`, kind: 'list', value: false, nullable, item, imageList: list ?? null, schema: x};
    }
    case 'object': {
      if (hasProperties(x)) {
        const base = `${ctx.owner}${ident(ctx.item ? singular(ctx.wire) : ctx.wire)}`;
        let name = base;
        for (let n = 2; takenNames().has(name); n++) name = `${base}${n}`;
        const doc = x.description
          ? sentence(x.description)
          : ctx.item
            ? `One entry of <see cref="${ctx.owner}"/>'s <c>${xml(ctx.wire)}</c>.`
            : `The <c>${xml(ctx.wire)}</c> of <see cref="${ctx.owner}"/>.`;
        defineClass(name, x, {side: ctx.side, doc, entry: ctx.imageEntry ?? null});
        return {cs: name, kind: 'class', value: false, nullable, schema: x};
      }
      const extra = x.additionalProperties;
      const value = extra && extra !== true ? typeOf(extra, {...ctx, wire: `${ctx.wire}Value`}) : anyType(request, false, {});
      return {cs: `IReadOnlyDictionary<string, ${itemDecl(value)}>`, kind: 'map', value: false, nullable, item: value, schema: x};
    }
    default:
      throw new Error(`unknown type ${types[0]} at ${ctx.owner}.${ctx.wire}`);
  }
}

/** A value of any JSON: what the caller sends (object) or what the API sent (JsonElement). */
const anyType = (request, nullable, schema) => ({cs: request ? 'object' : 'JsonElement', kind: 'any', value: !request, nullable, schema});

/** A list item's or map value's declared type: nullable only when the schema allows null. */
const itemDecl = (t) => `${t.cs}${t.nullable ? '?' : ''}`;

function propertyDoc(x, t, wire) {
  const target = x?.$ref ? S[refName(x.$ref)] : null;
  const s = deref(x) ?? {};
  const parts = [];
  const description = x?.description ?? (x?.oneOf ?? x?.anyOf)?.map(deref).find((v) => v?.description)?.description ?? target?.description;
  if (description) parts.push(sentence(description));
  const values = t.kind === 'list' ? t.item.schema?.enum : s.enum;
  if (s.const !== undefined) parts.push(`Always ${code(s.const)}.`);
  else if (values) {
    const notes = (t.kind === 'list' ? t.item.schema?.['x-enum-descriptions'] : s['x-enum-descriptions']) ?? [];
    const list = values.map((v, i) => (notes[i] ? `${code(v)} (${xml(notes[i])})` : code(v))).join(', ');
    parts.push(`${t.kind === 'list' ? 'Each one of' : 'One of'} ${list}${t.constants ? ` (see <see cref="${t.constants}"/>)` : ''}.`);
  }
  if (s.default !== undefined) parts.push(`Default: ${code(s.default)}.`);
  if (s.format === 'date' && !/YYYY/.test(parts.join(' '))) parts.push('A date, <c>YYYY-MM-DD</c>.');
  if (s.format === 'date-time') parts.push('An ISO 8601 date and time.');
  if (s['x-verisec-image-token']) parts.push('Passed through unchanged (a token, not an image).');
  if (t.kind === 'image') parts.push('Build it with <see cref="Image.FromPath"/>, <see cref="Image.FromBytes"/>, <see cref="Image.FromStream"/> or <see cref="Image.FromBase64"/>.');
  if (t.kind === 'file') parts.push('Build it with <see cref="FileInput.FromPath"/>, <see cref="FileInput.FromBytes"/> or <see cref="FileInput.FromStream"/>.');
  if (t.kind === 'list' && t.imageList && !t.imageList.imageKey) parts.push('Each entry is an <see cref="Image"/>.');
  if (t.kind === 'list' && t.imageList?.imageKey) {
    const fill = [t.imageList.indexKey && `<c>${t.imageList.indexKey}</c>`, t.imageList.idKey && `<c>${t.imageList.idKey}</c>`].filter(Boolean).join(' and ');
    parts.push(`An entry can be an <see cref="Image"/> on its own${fill ? `; ${fill} ${t.imageList.indexKey && t.imageList.idKey ? 'are' : 'is'} filled in when left out` : ''}.`);
  }
  if (parts.length === 0) parts.push(`The <c>${xml(wire)}</c> ${t.kind === 'class' ? 'object' : t.kind === 'list' ? 'list' : 'field'}.`);
  return parts.join(' ');
}

function defineClass(name, schema, {side, doc, root = false, open = false, entry = null}) {
  if (classes.has(name)) throw new Error(`two types want the name ${name}`);
  if (HAND_WRITTEN.has(name)) throw new Error(`the schema ${name} takes the name of a hand-written type`);
  const def = {name, side, doc, props: [], root, open, entry, extension: schema.additionalProperties !== false};
  classes.set(name, def);
  if (open) return def;
  const required = new Set(schema.required ?? []);
  const used = new Set([name]);
  for (const [wire, child] of Object.entries(schema.properties ?? {})) {
    let prop = ident(wire);
    if (used.has(prop) || RESERVED_MEMBERS.has(prop)) prop = `${prop}Value`;
    while (used.has(prop)) prop = `${prop}_`;
    used.add(prop);
    const t = typeOf(child, {owner: name, wire, side});
    def.props.push({wire, prop, t, required: required.has(wire), doc: propertyDoc(child, t, wire), described: !!(child?.description ?? deref(child)?.description), schema: child});
  }
  if (entry) {
    const key = def.props.find((p) => p.wire === entry.imageKey);
    if (!key || key.t.kind !== 'image') throw new Error(`${name}: the image list's imageKey ${entry.imageKey} is not an image field`);
    const otherRequired = def.props.filter((p) => p.required && p !== key);
    if (otherRequired.length) throw new Error(`${name}: an image list entry with required fields besides the image (${otherRequired.map((p) => p.wire)})`);
    def.entryProp = key.prop;
  }
  return def;
}

// component schemas, in spec order
for (const [name, x] of Object.entries(S)) {
  const side = requestSchemas.has(name) ? 'request' : 'answer';
  if (isStringSchema(x)) {
    constants.push({name, values: x.enum ?? [], doc: x.description});
    continue;
  }
  if (x.oneOf || x.anyOf || x.allOf) throw new Error(`${name}: top-level oneOf/anyOf/allOf is not supported yet`);
  if (openTypes.has(name)) {
    defineClass(name, x, {side, doc: x.description ? sentence(x.description) : `The full result of <c>${name}</c>.`, root: true, open: true});
    continue;
  }
  if (isMapSchema(x)) {
    const extra = x.additionalProperties;
    const value = extra && extra !== true ? typeOf(extra, {owner: name, wire: 'value', side}) : anyType(side === 'request', false, {});
    maps.push({name, value, doc: x.description});
    continue;
  }
  if (!hasProperties(x)) throw new Error(`unhandled schema ${name}`);
  let doc = x.description ? sentence(x.description) : null;
  const op = opOfParams.get(name);
  if (!doc && op) doc = `The parameters of ${xml(op.op.summary)} (<c>${xml(op.id)}</c>, <c>${op.verb.toUpperCase()} ${xml(op.route)}</c>).`;
  const env = opOfEnvelope.get(name);
  if (!doc && env) doc = `The answer of ${xml(env.op.summary)} as it comes on the wire: <c>{ok, request_id, latency_ms, data, warnings, error}</c>. The methods return its <c>data</c> (<see cref="${env.answer}"/>).`;
  defineClass(name, x, {side, doc: doc ?? `The <c>${name}</c> object.`, root: answerRoots.has(name)});
}

// query parameters of the operations without a body, named by x-params-type (BankLookupParams)
for (const o of operations) {
  if (o.json || o.form || o.queryParams.length === 0) continue;
  if (!o.paramsType || S[o.paramsType]) throw new Error(`${o.id}: query parameters need an x-params-type that is not a schema`);
  const schema = {type: 'object', properties: {}, required: []};
  for (const p of o.queryParams) {
    schema.properties[p.name] = {...p.schema, description: p.description ?? p.schema?.description};
    if (p.required) schema.required.push(p.name);
  }
  defineClass(o.paramsType, schema, {side: 'request', doc: `The query parameters of ${xml(o.op.summary)} (<c>${xml(o.id)}</c>, <c>${o.verb.toUpperCase()} ${xml(o.route)}</c>).`});
  o.queryType = o.paramsType;
}

/**
 * The "Returns" list of an operation's description (- `faces[].roi`: the face box) documents its answer's fields;
 * the spec's answer schemas mostly have none. Bullets naming a field the schema lacks are reported.
 */
const undocumentedReturns = [];
for (const o of operations) {
  const def = classes.get(o.answer);
  if (!def || def.open) continue;
  for (const m of String(o.op.description ?? '').matchAll(/^- (.*?`[^\n]*?)`:\s+(.+)$/gm)) {
    const names = [...(m[1] + '`').matchAll(/`([^`]+)`/g)].flatMap((x) => x[1].split('/')).map((x) => x.trim()).filter((x) => x && !x.includes('<'));
    let context = def; // `results[].listings / disputed_by`: a bare name after the first is its sibling
    for (const name of names) {
      let prop = null;
      for (const start of name.includes('.') || context === def ? [def] : [def, context]) {
        let target = start;
        let owner = start;
        for (const seg of name.split('.')) {
          const wire = seg.replace(/\[\]$/, '');
          owner = target;
          prop = target?.props.find((p) => p.wire === wire) ?? null;
          if (!prop) break;
          const inner = prop.t.kind === 'list' ? prop.t.item : prop.t;
          target = inner.kind === 'class' ? classes.get(inner.cs) : null;
        }
        if (prop) {
          context = owner;
          break;
        }
      }
      if (!prop) {
        undocumentedReturns.push(`${o.id}: ${name}`);
        continue;
      }
      if (!prop.described) {
        prop.doc = sentence(m[2].replace(/^\s*(.)/, (c) => c.toUpperCase()));
        prop.described = true;
      }
    }
  }
}

/** Where a request's image lists are (dotted when nested), for the SDK to fill in index and ids. */
function imageLists(name, prefix = '') {
  const out = [];
  for (const p of classes.get(name)?.props ?? []) {
    const at = prefix ? `${prefix}.${p.wire}` : p.wire;
    if (p.t.kind === 'list' && p.t.imageList?.imageKey) out.push({path: at, ...p.t.imageList});
    else if (p.t.kind === 'class') out.push(...imageLists(p.t.cs, at));
  }
  return out;
}

// ------------------------------------------------------------------------------------------------ Models.g.cs

const HEADER = `// <auto-generated>
// Generated by scripts/generate.mjs from spec/openapi.json (VeriSec API ${spec.info.version}).
// Do not edit by hand: change the spec or the generator, then run \`node scripts/generate.mjs\`.
// </auto-generated>
#nullable enable
`;

function renderClass(def) {
  let out = docBlock([def.doc], '');
  if (def.open) {
    out += `[JsonConverter(typeof(OpenResultConverter<${def.name}>))]\npublic sealed class ${def.name} : OpenResult\n{\n}\n`;
    return out;
  }
  const request = def.side === 'request';
  out += `public sealed class ${def.name}${def.root ? ' : ApiResult' : ''}\n{\n`;
  const members = [];
  for (const p of def.props) {
    const required = request && p.required && !p.t.nullable;
    const decl = `${p.t.cs}${required ? '' : '?'}`;
    let m = docBlock([p.doc], '    ');
    m += `    [JsonPropertyName(${csString(p.wire)})]\n`;
    m += `    public ${required ? 'required ' : ''}${decl} ${p.prop} { get; ${request ? 'set' : 'init'}; }\n`;
    members.push(m);
  }
  if (def.extension) {
    members.push(
      request
        ? `    /// <summary>Fields to send that this version of the library does not know yet, by their API name. They go on the wire as they are.</summary>\n    [JsonExtensionData]\n    public IDictionary<string, object?>? AdditionalProperties { get; set; }\n`
        : `    /// <summary>Fields the API sent that this class does not declare, as raw JSON.</summary>\n    [JsonExtensionData]\n    public IDictionary<string, JsonElement>? AdditionalProperties { get; init; }\n`,
    );
  }
  if (def.entry) {
    members.push(
      `    /// <summary>An entry that is just <paramref name="image"/>: the rest of it is filled in when the request is sent.</summary>\n` +
        `    /// <param name="image">The image of the entry.</param>\n` +
        `    public static implicit operator ${def.name}(Image image) => new() { ${def.entryProp} = image };\n`,
    );
  }
  out += members.join('\n');
  out += '}\n';
  return out;
}

function renderConstants(c) {
  const used = new Set([c.name]);
  const members = c.values.map((v) => {
    let name = ident(v);
    while (used.has(name)) name += '_';
    used.add(name);
    return `    /// <summary><c>${xml(v)}</c></summary>\n    public const string ${name} = ${csString(v)};\n`;
  });
  const doc = [
    c.doc ? sentence(c.doc) : `The <c>${c.name}</c> strings.`,
    c.values.length
      ? `The values the API uses today. Fields of this kind stay <see cref="string"/>, so a value added later never breaks reading an answer.`
      : `Fields of this kind are a <see cref="string"/>.`,
  ];
  return `${docBlock(doc, '')}public static class ${c.name}\n{\n${members.join('\n')}}\n`;
}

function renderMap(m) {
  const doc = [m.doc ? sentence(m.doc) : `The <c>${m.name}</c> map.`, 'A dictionary of the fields by name.'];
  return `${docBlock(doc, '')}public sealed class ${m.name} : Dictionary<string, ${itemDecl(m.value)}>\n{\n}\n`;
}

let models = `${HEADER}
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VeriSec;
`;
for (const c of constants) models += `\n${renderConstants(c)}`;
for (const m of maps) models += `\n${renderMap(m)}`;
for (const def of classes.values()) models += `\n${renderClass(def)}`;

// ------------------------------------------------------------------------------------------------ Resources.g.cs

const tree = {children: new Map(), ops: [], segs: []};
for (const o of operations) {
  let node = tree;
  for (const seg of o.segs) {
    if (!node.children.has(seg)) node.children.set(seg, {children: new Map(), ops: [], segs: [...node.segs, seg]});
    node = node.children.get(seg);
  }
  node.ops.push(o);
}
const resourceClass = (node) => `${node.segs.map(ident).join('')}Resource`;
for (const node of (function* walk(n) { for (const c of n.children.values()) { yield c; yield* walk(c); } })(tree)) {
  if (HAND_WRITTEN.has(resourceClass(node)) || S[resourceClass(node)]) throw new Error(`resource class ${resourceClass(node)} collides`);
}

const price = (o) => (o.op['x-price'] ? `Price: ${o.op['x-price']} credits per successful call.` : 'Free: not charged.');
const firstParagraph = (o) => (o.op.description ? String(o.op.description).split(/\n\s*\n/)[0] : '');

function renderMethod(o, fields) {
  const name = `${ident(o.method)}Async`;
  const http = `HttpMethod.${o.verb[0].toUpperCase()}${o.verb.slice(1)}`;
  const envelope = o.envelope === 'data' ? 'Envelope.Data' : 'Envelope.Object';
  const pathArgs = o.pathParams.map((p) => `string ${camel(p.name)}, `).join('');
  const pathDocs = o.pathParams.map((p) => `    /// <param name="${camel(p.name).replace('@', '')}">${p.description ? sentence(p.description) : `The <c>${xml(p.name)}</c>.`}</param>\n`).join('');
  const pathChecks = o.pathParams.map((p) => `        ArgumentException.ThrowIfNullOrEmpty(${camel(p.name)});\n`).join('');
  const route = o.pathParams.length ? `$"${o.route.replace(/\{([^}]+)\}/g, (_, p) => `{Uri.EscapeDataString(${camel(p)})}`)}"` : csString(o.route);
  const returns = o.envelope === 'data'
    ? `The answer's <c>data</c>${openTypes.has(o.answer) ? ' (the engine\'s full result)' : ''}, with <see cref="ApiResult.LastResponse"/>.`
    : `The answer${openTypes.has(o.answer) ? ' (the engine\'s full result)' : ''}, with <see cref="ApiResult.LastResponse"/>.`;
  const docs = [`${xml(o.op.summary)}: <c>${o.verb.toUpperCase()} ${xml(o.route)}</c>.`, prose(firstParagraph(o)), price(o)];

  let params = '';
  let paramDocs = '';
  let call;
  if (o.json) {
    params = `${o.paramsType} parameters, `;
    paramDocs = `    /// <param name="parameters">The request.</param>\n`;
    const lists = imageLists(o.paramsType);
    let plan = 'ImagePlan.None';
    if (lists.length) {
      plan = `${ident(o.method)}Images`;
      const entries = lists.map((l) => `new ImageList(${[csString(l.path), csString(l.imageKey), l.indexKey ? csString(l.indexKey) : 'null', l.idKey ? csString(l.idKey) : 'null', l.itemLabel ? csString(l.itemLabel) : 'null'].join(', ')})`);
      fields.push(`    private static readonly ImagePlan ${plan} = new(${entries.join(', ')});\n`);
    }
    call = `_transport.JsonAsync<${o.answer}>(${http}, ${route}, parameters, ${plan}, ${envelope}, ${o.sdkSource}, options, cancellationToken)`;
  } else if (o.form) {
    params = `${o.paramsType} parameters, `;
    paramDocs = `    /// <param name="parameters">The upload: the file and its options, sent as <c>multipart/form-data</c>.</param>\n`;
    call = `_transport.UploadAsync<${o.answer}>(${http}, ${route}, parameters, ${envelope}, ${o.sdkSource}, options, cancellationToken)`;
  } else if (o.queryType) {
    const optional = !o.queryParams.some((p) => p.required);
    params = `${o.queryType}${optional ? '? parameters = null' : ' parameters'}, `;
    paramDocs = `    /// <param name="parameters">The query parameters.</param>\n`;
    call = `_transport.QueryAsync<${o.answer}>(${http}, ${route}, parameters, ${envelope}, options, cancellationToken)`;
  } else {
    call = `_transport.QueryAsync<${o.answer}>(${http}, ${route}, null, ${envelope}, options, cancellationToken)`;
  }
  const tags =
    `${pathDocs}${paramDocs}` +
    `    /// <param name="options">This call's timeout, retries and extra headers.</param>\n` +
    `    /// <param name="cancellationToken">Cancels the call.</param>\n` +
    `    /// <returns>${returns}</returns>\n` +
    `    /// <exception cref="ApiException">The API answered with an error; the subclass says which (<see cref="InsufficientCreditsException"/> when the credits ran out). Nothing was charged.</exception>\n` +
    `    /// <exception cref="ApiConnectionException">No answer: the API could not be reached, the connection failed, or the call timed out (<see cref="ApiTimeoutException"/>).</exception>\n`;
  const signature = `public Task<${o.answer}> ${name}(${pathArgs}${params}RequestOptions? options = null, CancellationToken cancellationToken = default)`;
  if (o.json || o.form) {
    return `${docBlock(docs, '    ')}${tags}    ${signature}\n    {\n        ArgumentNullException.ThrowIfNull(parameters);\n${pathChecks}        return ${call};\n    }\n`;
  }
  return `${docBlock(docs, '    ')}${tags}    ${signature}\n    {\n${pathChecks}        return ${call};\n    }\n`;
}

function resourceDoc(node) {
  const ops = [];
  (function collect(n) {
    n.ops.forEach((o) => ops.push(o));
    n.children.forEach(collect);
  })(node);
  return `The <c>${xml(node.segs.join('.'))}</c> APIs: ${ops.map((o) => xml(o.op.summary)).join(', ')}.`;
}

const resourceClasses = [];
function renderResource(node) {
  const name = resourceClass(node);
  const children = [...node.children.values()];
  const fields = [];
  const methods = node.ops.map((o) => renderMethod(o, fields));
  const props = children.map((c) => `${docBlock([resourceDoc(c)], '    ')}    public ${resourceClass(c)} ${ident(c.segs.at(-1))} { get; }\n`);
  const ctor = `    internal ${name}(HttpTransport transport)\n    {\n        _transport = transport;\n${children.map((c) => `        ${ident(c.segs.at(-1))} = new ${resourceClass(c)}(transport);\n`).join('')}    }\n`;
  resourceClasses.push(
    `${docBlock([resourceDoc(node)], '')}public sealed class ${name}\n{\n${fields.join('')}${fields.length ? '\n' : ''}    private readonly HttpTransport _transport;\n\n${ctor}\n${[...props, ...methods].join('\n')}}\n`,
  );
  children.forEach(renderResource);
}
const top = [...tree.children.values()];
top.forEach(renderResource);

const resources = `${HEADER}
using System.Diagnostics.CodeAnalysis;
using VeriSec.Core;

namespace VeriSec;

public sealed partial class VeriSecClient
{
${top.map((node) => `${docBlock([resourceDoc(node)], '    ')}    public ${resourceClass(node)} ${ident(node.segs[0])} { get; private set; }\n`).join('\n')}
    [MemberNotNull(${top.map((n) => `nameof(${ident(n.segs[0])})`).join(', ')})]
    private void InitializeResources(HttpTransport transport)
    {
${top.map((node) => `        ${ident(node.segs[0])} = new ${resourceClass(node)}(transport);\n`).join('')}    }
}

${resourceClasses.join('\n')}`;

// ------------------------------------------------------------------------------------------------ the tests

/** A C# expression for an example value of type t, with images from files and bytes, image lists as bare images. */
function csValue(t, value, state) {
  if (value === null) return 'null';
  switch (t.kind) {
    case 'image':
      return state.image();
    case 'file':
      return 'FileInput.FromPath(Assets.PngPath)';
    case 'any':
      if (typeof value === 'string') return csString(value);
      if (typeof value === 'boolean') return String(value);
      if (typeof value === 'number') return Number.isInteger(value) ? String(value) : `${value}d`;
      return `Assets.Json(${csString(JSON.stringify(value))})`;
    case 'list':
      if (t.imageList) return `[${value.map(() => state.image()).join(', ')}]`;
      return `[${value.map((v) => csValue(t.item, v, state)).join(', ')}]`;
    case 'map':
      return `new Dictionary<string, ${itemDecl(t.item)}> { ${Object.entries(value).map(([k, v]) => `[${csString(k)}] = ${csValue(t.item, v, state)}`).join(', ')} }`;
    case 'class': {
      const def = classes.get(t.cs);
      const parts = [];
      for (const [wire, v] of Object.entries(value)) {
        const p = def.props.find((q) => q.wire === wire);
        if (!p) throw new Error(`${t.cs}: the example has ${wire}, which the schema does not declare`);
        parts.push(`${p.prop} = ${csValue(p.t, v, state)}`);
      }
      for (const p of def.props) if (p.required && !(p.wire in value)) throw new Error(`${t.cs}: the example lacks the required ${p.wire}`);
      return `new ${t.cs} { ${parts.join(', ')} }`;
    }
    default:
      switch (t.cs) {
        case 'string':
          return csString(value);
        case 'bool':
          return String(value);
        case 'long':
          return `${value}L`;
        case 'int':
          return String(value);
        default:
          return Number.isInteger(value) ? String(value) : String(value);
      }
  }
}

let uploads = 0;
const testMethods = operations.map((o) => {
  let n = 0;
  const state = {image: () => (n++ % 2 ? 'Image.FromBytes(Assets.Png)' : 'Image.FromPath(Assets.PngPath)')};
  const resource = o.segs.map(ident).join('.');
  const method = `${ident(o.method)}Async`;
  let args;
  let query = 'null';
  if (o.json) {
    args = csValue({kind: 'class', cs: o.paramsType}, o.json.example ?? {}, state);
  } else if (o.form) {
    const def = classes.get(o.paramsType);
    const file = uploads++ % 2 ? 'FileInput.FromBytes(Assets.Png, "scan.png")' : 'FileInput.FromPath(Assets.PngPath)';
    const extras = def.props.filter((p) => p.t.kind !== 'file' && o.form.example?.[p.wire] !== undefined).map((p) => `${p.prop} = ${csValue(p.t, o.form.example[p.wire], state)}`);
    args = `new ${o.paramsType} { ${[`${def.props.find((p) => p.t.kind === 'file').prop} = ${file}`, ...extras].join(', ')} }`;
  } else {
    const pathArgs = o.pathParams.map((p) => csString(p.example ?? p.schema?.example ?? 'x'));
    const given = o.queryParams.filter((p) => p.example !== undefined);
    const queryArgs = o.queryType
      ? [`new ${o.queryType} { ${given.map((p) => `${classes.get(o.queryType).props.find((q) => q.wire === p.name).prop} = ${csString(p.example)}`).join(', ')} }`]
      : [];
    if (given.length) query = `new Dictionary<string, string> { ${given.map((p) => `[${csString(p.name)}] = ${csString(p.example)}`).join(', ')} }`;
    args = [...pathArgs, ...queryArgs].join(', ');
  }
  const sentPath = o.route.replace(/\{([^}]+)\}/g, (_, p) => o.pathParams.find((x) => x.name === p)?.example ?? 'x');
  return `    [Fact(DisplayName = ${csString(`${o.id} (${o.verb.toUpperCase()} ${o.route})`)})]
    public async Task ${o.segs.map(ident).join('')}${ident(o.method)}()
    {
        using var client = Server.Client();
        var result = await client.${resource}.${method}(${args});
        await Server.AssertAnsweredAsync(${csString(o.id)}, result, ${csString(sentPath)}, upload: ${!!o.form}, query: ${query});
    }
`;
});

const tests = `${HEADER}
using VeriSec.Tests.Support;

namespace VeriSec.Tests.Integration;

/// <summary>
/// Every operation of the spec through the SDK, against the shared test server: the request built from the spec's
/// example with images as files and bytes (image lists as bare images), the answer equal to the spec's example.
/// </summary>
[Collection(ServerCollection.Name)]
public sealed class EveryOperationTests(TestServer server) : IAsyncLifetime
{
    private TestServer Server { get; } = server;

    public Task InitializeAsync() => Server.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

${testMethods.join('\n')}}
`;

// ------------------------------------------------------------------------------------------------ write

const write = (file, text) => {
  fs.mkdirSync(path.dirname(file), {recursive: true});
  fs.writeFileSync(file, text.replace(/\n{3,}/g, '\n\n').replace(/\r\n/g, '\n'));
  console.log(`wrote ${path.relative(DOTNET, file)}`);
};
write(MODELS, models);
write(RESOURCES, resources);
write(TESTS, tests);
const counts = {
  operations: operations.length,
  resources: [...(function* walk(n) { for (const c of n.children.values()) { yield c; yield* walk(c); } })(tree)].length,
  classes: classes.size,
  componentClasses: [...classes.keys()].filter((n) => S[n]).length,
  open: openTypes.size,
  constants: constants.length,
  maps: maps.length,
};
if (undocumentedReturns.length) console.log(`note: ${undocumentedReturns.length} "Returns" bullets name fields their answer schema does not declare: ${undocumentedReturns.join(', ')}`);
console.log(
  `${counts.operations} operations in ${counts.resources} resources; ${counts.componentClasses + counts.constants + counts.maps} of ${Object.keys(S).length} component schemas as types ` +
    `(${counts.componentClasses} classes incl. ${counts.open} open results, ${counts.constants} string constant sets, ${counts.maps} maps), ${counts.classes - counts.componentClasses} nested and query types`,
);
