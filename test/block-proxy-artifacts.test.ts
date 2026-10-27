// Ported from the upstream suite (MIT, https://github.com/wtogami/qwen-block-proxy-artifacts).
// The original exercised two opencode entrypoints plus a loader-contract test mirroring opencode's
// plugin loader; Pi has one entrypoint, so those become: the default export is a factory that registers
// a tool_call handler, and that handler blocks and permits through the same verdict().
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import extension, { BLOCKED, LOCAL_TOOLS, OPTIONAL, findBlocked, strings, verdict } from "../extensions/block-proxy-artifacts.ts";

// Dead-proxy URL fixture reconstructed from a real hallucinated call. Assembled from fragments so this
// source never contains a contiguous blocklisted token — otherwise the live fence would block any agent
// trying to edit this test.
const DEAD_URL = [
  "https://routify",
  "-file",
  "-proxy-sg.oss-ap-southeast-1",
  ".aliyuncs.com/",
  "proxy_",
  "temp_file/production/2026-09-21/trace_2101843517899439873655976e0e98/",
  "requestId_6b581d20398a4d18b56e18d56518c18a/9296a8761c29666465047035c00e57da",
  "?Expires=1814047991&OSSAccessKeyId=REPLACEDPLACEHOLDER&Signature=Gz9%2F3jH",
].join("");

const CLEAN_URLS = [
  "https://docs.python.org/3/library/pathlib.html",
  "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/403",
  "https://pkg.go.dev/net/http",
];

type ToolCallHandler = (event: { toolName: string; input: unknown }) =>
  | { block?: boolean; reason?: string }
  | undefined;

// Load the extension against a fake Pi host and hand back its tool_call handler.
function toolCallHandler(): ToolCallHandler {
  const handlers: Record<string, Function> = {};
  extension({ on: (name: string, handler: Function) => (handlers[name] = handler) } as never);
  const hook = handlers.tool_call as ToolCallHandler | undefined;
  assert.ok(hook, "extension must register a tool_call handler");
  assert.ok(handlers.session_start, "extension must reset per-session state on session_start");
  return (event) => hook(event);
}

// A fresh runtime is Pi's equivalent of a fresh session for guidance purposes.
function freshReason() {
  const handlers: Record<string, Function> = {};
  extension({ on: (name: string, handler: Function) => (handlers[name] = handler) } as never);
  const hook = handlers.tool_call as ToolCallHandler;
  return (input: unknown) => {
    const r = hook({ toolName: "webfetch", input });
    return r ? String(r.reason) : "";
  };
}

function nest(depth: number, leaf: unknown): unknown {
  let v = leaf;
  for (let i = 0; i < depth; i++) v = [v];
  return v;
}

test("fixtures: three live rules, exact incident host first, one parked rule", () => {
  assert.equal(BLOCKED.length, 3);
  assert.ok(BLOCKED.every((b) => b.why.length > 0));
  assert.equal(OPTIONAL.length, 1);
  const hit = findBlocked(DEAD_URL);
  assert.ok(hit);
  assert.equal(hit.why, "observed incident host (dead relay bucket)");
});

test("strings(): primitives", () => {
  assert.deepEqual([...strings("hello")], ["hello"]);
  for (const junk of [42, null, undefined, true, Symbol("s"), () => 0]) {
    assert.deepEqual([...strings(junk)], []);
  }
});

test("strings(): arrays, object values, and object keys", () => {
  const found = new Set(strings({ a: ["x"], b: { c: "y" }, n: null }));
  assert.deepEqual([...found].sort(), ["a", "b", "c", "n", "x", "y"].sort());
});

test("strings(): depth cap is 6 container levels", () => {
  assert.ok([...strings(nest(6, "leaf"))].includes("leaf"));
  assert.ok(![...strings(nest(7, "leaf"))].includes("leaf"));
});

test("findBlocked(): exact-host rule, case-insensitive; hostless variants pass by design", () => {
  const INCIDENT = "observed incident host (dead relay bucket)";
  assert.equal(findBlocked(DEAD_URL)?.why, INCIDENT);
  assert.equal(findBlocked(DEAD_URL.toUpperCase())?.why, INCIDENT);

  // Deliberate under-inclusion: the relay-label rule is host-anchored — routify + file must sit
  // host-adjacent to an aliyuncs.com/.io endpoint. Separator-mutated or region-shifted bucket labels on
  // non-aliyuncs hosts pass until observed; if one ever does, re-add a token rule.
  const underscoreHost = ["https://routify", "_file", "_proxy-sg.example.org/download"].join("");
  const otherRegion = ["https://routify", "-file", "-proxy-hz.example.net/download"].join("");
  assert.equal(findBlocked(underscoreHost), null);
  assert.equal(findBlocked(otherRegion), null);
});

test("findBlocked(): same relay bucket on alternate OSS endpoint forms", () => {
  // Recorded dials used the dual-stack endpoint spelling, Alibaba's documented
  // `<bucket>.<region>.oss.aliyuncs.com` form. Fragments keep this file clean.
  const RELAY = "relay bucket label (any routify-file-* form) on an Aliyun OSS endpoint, com or io TLD";
  const dualStack = [
    "https://routify", "-file", "-proxy-sg",
    ".ap-southeast-1.oss", ".aliyuncs.com/", "proxy_", "temp_file/production/x",
  ].join("");
  const internal = [
    "https://routify", "-file", "-proxy-sg",
    ".oss-ap-southeast-1-internal", ".aliyuncs.com/x",
  ].join("");
  assert.equal(findBlocked({ url: dualStack })?.why, RELAY);
  assert.equal(findBlocked({ url: internal })?.why, RELAY);
  // Different bucket on the same alternate endpoint: stays clean.
  assert.equal(findBlocked("https://my-app.ap-southeast-1.oss.aliyuncs.com/x"), null);
  // Token mentioned in prose, not as a host: stays clean.
  assert.equal(
    findBlocked("audit notes: the routify-file-proxy bucket uploads to aliyuncs.com daily"),
    null,
  );
});

test("findBlocked(): relay-label family members, including proxy-less labels and the io TLD", () => {
  const RELAY = "relay bucket label (any routify-file-* form) on an Aliyun OSS endpoint, com or io TLD";
  const oversea = [
    "https://routify", "-file", "-oversea",
    ".oss-acdr-ut-1", ".aliyuncs.com/", "proxy_", "temp_file/production/x",
  ].join("");
  const accelerate = [
    "https://routify", "-file", "-proxy",
    ".oss-accelerate", ".aliyuncs.com/proxy/temp/x",
  ].join("");
  const cnBeijing = [
    "https://routify", "-file", "-proxy",
    ".oss-cn-beijing", ".aliyuncs.com/proxy/x",
  ].join("");
  const euIo = [
    "https://routify", "-file", "-proxy-eu",
    ".oss-eu-west-3", ".aliyuncs.io/proxy_temp_file/x",
  ].join("");
  for (const url of [oversea, accelerate, cnBeijing, euIo])
    assert.equal(findBlocked({ format: "markdown", url })?.why, RELAY, url);
});

test("findBlocked(): passes legitimate and near-miss input", () => {
  for (const url of CLEAN_URLS) assert.equal(findBlocked({ url }), null);
  assert.equal(findBlocked("routify is also a logistics company"), null);
  assert.equal(findBlocked({ path: "/var/tmp/proxy_temp_file/report.csv" }), null);
  assert.equal(findBlocked("https://my-backup.oss-cn-hangzhou.aliyuncs.com/dump.tar.gz"), null);
  assert.equal(findBlocked("ROUTIFY REPORT 2026 file proxy"), null);

  // A legitimate relay operator's own bucket may host signed temp-file exports under the same path
  // scheme, and those can validly return 200.
  const legitRelayExport = [
    "https://my-relay.oss-cn-hangzhou",
    ".aliyuncs.com/",
    "proxy_",
    "temp_file/signed-export?sig=valid",
  ].join("");
  assert.equal(findBlocked(legitRelayExport), null);
});

test("findBlocked(): scans object keys, not just values", () => {
  assert.ok(findBlocked({ [DEAD_URL]: "metadata" }));
});

test("findBlocked(): nested args respect the depth cap", () => {
  assert.ok(findBlocked(nest(6, DEAD_URL)));
  assert.equal(findBlocked(nest(7, DEAD_URL)), null);
});

test("findBlocked(): tolerates empty and odd argument shapes", () => {
  for (const args of [undefined, null, {}, [], { a: { b: [null, 1, true] } }]) {
    assert.equal(findBlocked(args), null);
  }
});

test("tool_call: hard-blocks real call shapes from the incident", () => {
  const hook = toolCallHandler();
  const blockedShapes: Record<string, unknown>[] = [
    // a fetch tool: the failed call that triggered the original incident
    { url: DEAD_URL, format: "markdown" },
    // a batch fetch tool: dead URL hidden in a urls array
    { urls: [CLEAN_URLS[0], DEAD_URL], maxCharacters: 5000 },
    // bash: curl of the dead URL
    { command: `curl -s ${DEAD_URL} | head` },
    // subagent task: dead URL inside a deeply nested prompt
    { prompt: { context: "fetch", urls: [DEAD_URL] } },
  ];

  for (const input of blockedShapes) {
    const result = hook({ toolName: "bash", input });
    assert.equal(result?.block, true);
    assert.match(String(result?.reason), /Blocked by block-proxy-artifacts policy/);
    assert.match(String(result?.reason), /Do NOT retry/);
  }
});

test("tool_call: lets clean calls through untouched", () => {
  const hook = toolCallHandler();
  for (const url of CLEAN_URLS) {
    assert.equal(hook({ toolName: "webfetch", input: { url, format: "text", timeout: 120 } }), undefined);
  }
  assert.equal(hook({ toolName: "webfetch", input: undefined }), undefined);
  assert.equal(hook({ toolName: "webfetch", input: {} }), undefined);
});

test("tool_call: local file tools are exempt, everything else is scanned", () => {
  const hook = toolCallHandler();
  // The exempt set is exactly the tools that cannot open a socket, nothing more.
  assert.deepEqual([...LOCAL_TOOLS].sort(), ["edit", "find", "grep", "ls", "read", "write"]);
  for (const toolName of LOCAL_TOOLS) {
    const input = { path: DEAD_URL, content: DEAD_URL, pattern: DEAD_URL };
    assert.equal(hook({ toolName, input }), undefined, toolName);
  }
  // Names this file cannot enumerate stay fenced, literal in a nested array included.
  for (const toolName of ["webfetch", "bash", "mcp__brave__web_fetch", "agent_browser"]) {
    const result = hook({ toolName, input: { urls: [CLEAN_URLS[0], DEAD_URL] } });
    assert.equal(result?.block, true, toolName);
    assert.match(String(result?.reason), /Blocked by block-proxy-artifacts policy/);
  }
});

test("tool_call: full guidance once per session, terse repeats, reset on session_start", () => {
  const handlers: Record<string, Function> = {};
  extension({ on: (name: string, handler: Function) => (handlers[name] = handler) } as never);
  const hook = handlers.tool_call as ToolCallHandler;
  const start = handlers.session_start as () => void;
  const args = { url: DEAD_URL };
  const FULL_MARKER = "Go back to the original publisher URL";

  assert.ok(String(hook({ toolName: "webfetch", input: args })?.reason).includes(FULL_MARKER));
  const repeat = hook({ toolName: "webfetch", input: args });
  assert.equal(repeat?.block, true);
  assert.ok(!String(repeat?.reason).includes(FULL_MARKER));
  assert.ok(String(repeat?.reason).includes("Do NOT retry"));
  // A new session in the same runtime gets the full teaching guidance again.
  start();
  assert.ok(String(hook({ toolName: "webfetch", input: args })?.reason).includes(FULL_MARKER));
});

// Upload-bucket and metadata fixtures (same fragment discipline as DEAD_URL: this file must never
// contain a contiguous match for these rules).
const UPLOAD_BUCKET_URL = ["https://sanmaohe", ".oss-cn-beijing", ".aliyuncs.com/upload/test.bin"].join("");
const UPLOAD_BUCKET_DUALSTACK = [
  "https://sanmaohe", ".oss-cn-beijing.oss", ".aliyuncs.com/upload/test.bin",
].join("");
const META_IP = ["http://169", ".254.169.254/latest/meta-data/iam/security-credentials/"].join("");
const META_IP_ALI = ["100.100", ".100.200"].join(""); // bare, no scheme
const META_NAME = ["http://metadata", ".google.internal/computeMetadata/v1/instance/"].join("");

const META_WHY = "cloud instance-metadata endpoint (temporary-credential surface; never needed by an agent task)";

test("rule 3: hard-blocks the upload-bucket shapes", () => {
  const hook = toolCallHandler();
  const bucketShapes: unknown[] = [
    { url: UPLOAD_BUCKET_URL, format: "markdown" },
    { urls: [CLEAN_URLS[0], UPLOAD_BUCKET_DUALSTACK], maxCharacters: 5000 },
    { command: `curl -s -m 10 -o /tmp/put_probe -X PUT --data-binary "PROBE_PAYLOAD" ${UPLOAD_BUCKET_URL} -w "HTTP:%{http_code}"` },
  ];
  for (const input of bucketShapes) {
    const result = hook({ toolName: "bash", input });
    assert.equal(result?.block, true);
    assert.match(String(result?.reason), /upload-target bucket/);
  }
});

test("parked metadata rule: passes the live fence, blocks when opted in", () => {
  const hook = toolCallHandler();
  const metaShapes: unknown[] = [
    { url: META_IP },
    { url: "http://" + META_IP_ALI + "/latest/meta-data/" },
    { url: META_NAME },
    { server: META_IP_ALI }, // bare metadata address as a plain argument value
  ];
  for (const input of metaShapes) {
    assert.equal(hook({ toolName: "webfetch", input }), undefined);
    assert.equal(findBlocked(input, OPTIONAL)?.why, META_WHY, JSON.stringify(input));
  }
  // Guidance still reads as credential framing on the first hit, terse on the repeat, and it never
  // repeats the fetch-the-publisher advice meant for relay links.
  const warned = { first: false };
  assert.match(String(verdict({ url: META_IP }, warned, OPTIONAL)), /credential/);
  assert.doesNotMatch(String(verdict({ url: META_IP }, { first: false }, OPTIONAL)), /publisher URL/);
  assert.match(String(verdict({ url: META_IP }, warned, OPTIONAL)), /credential surface/);
  assert.doesNotMatch(String(verdict({ url: META_IP }, warned, OPTIONAL)), /IAM/);
});

test("PI_BLOCK_PROXY_METADATA opts the parked rule into the live fence", async () => {
  // A separate module instance, so the env read at load time does not disturb the default fence.
  const url = "../extensions/block-proxy-artifacts.ts?opt-in=1";
  process.env.PI_BLOCK_PROXY_METADATA = "1";
  try {
    const mod = (await import(url)) as typeof import("../extensions/block-proxy-artifacts.ts");
    assert.equal(mod.BLOCKED.length, 4, "parked rule joins the live fence when opted in");
    const handlers: Record<string, Function> = {};
    mod.default({ on: (name: string, handler: Function) => (handlers[name] = handler) } as never);
    const result = handlers.tool_call!({ toolName: "webfetch", input: { url: META_IP } });
    assert.equal((result as { block?: boolean })?.block, true);
    assert.match(String((result as { reason?: string })?.reason), /credential/);
  } finally {
    delete process.env.PI_BLOCK_PROXY_METADATA;
  }
  assert.equal(BLOCKED.length, 3, "the default fence is unchanged by an opted-in instance");
});

test("near-misses pass through untouched, live rules and parked rule alike", () => {
  const nearMisses: unknown[] = [
    // the ordinary site that the bare bucket label actually resolves to
    { url: "https://sanmaoheling.com/blogs/news.atom" },
    { url: "https://my-backup.oss-cn-beijing.aliyuncs.com/legit-object.tar.gz" },
    { command: "grep -ri sanmaohe ./docs/" }, // label alone, no OSS endpoint
    { url: "http://169.254.1.1/other-link-local" }, // not the metadata address
    { url: "http://" + ["1", ".169.254", ".169.254"].join("") + "/longer-address" }, // digit-prefixed
    { url: "http://100.100.100.201/" }, // neighbour address
    { version: ["169.254", ".169.2540", "-1"].join("") }, // trailing digit
    { url: "https://metadata.example.com/google/internal" },
  ];
  for (const input of nearMisses) {
    assert.equal(findBlocked(input), null, `should pass: ${JSON.stringify(input)}`);
    assert.equal(findBlocked(input, OPTIONAL), null, `should pass the parked rule too: ${JSON.stringify(input)}`);
  }
});

test("relay rules keep publisher guidance", () => {
  // Upload-bucket rule: upload framing.
  assert.match(freshReason()({ url: UPLOAD_BUCKET_URL }), /upload endpoint/);
  // Relay rules unchanged: dead-relay publisher guidance.
  const relay = freshReason();
  assert.match(relay({ url: DEAD_URL }), /publisher URL/);
  assert.match(relay({ url: DEAD_URL }), /relay middlebox/);
});

test("self-compatibility: blocklist never matches this extension's own sources", () => {
  // If someone pastes a live proxy URL (or rewrites a regex to match its own source) into the extension
  // or its tests, an agent with the fence installed could no longer edit or grep these files. This test
  // makes that mistake fail the suite.
  for (const src of ["../extensions/block-proxy-artifacts.ts", "./block-proxy-artifacts.test.ts"]) {
    assert.equal(
      findBlocked(readFileSync(new URL(src, import.meta.url), "utf8")),
      null,
      `${src} contains a live token`,
    );
  }
});

test("Pi extension contract: default export is a factory registering tool_call", async () => {
  const mod = await import("../extensions/block-proxy-artifacts.ts");
  assert.equal(typeof mod.default, "function");
  const names: string[] = [];
  extension({ on: (name: string) => (names.push(name), () => {}) } as never);
  assert.deepEqual(names.sort(), ["session_start", "tool_call"]);
});
