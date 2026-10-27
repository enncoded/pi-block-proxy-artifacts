// block-proxy-artifacts: block hallucinated file-proxy artifact URLs before any tool dials out.
//
// Small Qwen builds fabricate signed Aliyun OSS "file proxy" links, the shape a cheap API-relay middlebox
// puts in place of an oversized tool output, and hand them to a fetch tool or `curl`. Nobody configured
// that host. The links cannot be fetched (the service answers 403), and each attempt burns an agent step,
// leaks a trace identifier to a third party, and leaves ~200 tokens of junk in the context that every
// later step re-reads. Rules, guidance text and forensics come from the opencode original:
// https://github.com/wtogami/qwen-block-proxy-artifacts
//
// Pi shape: `tool_call` is Pi's equivalent of `tool.execute.before`, returning `{ block, reason }` instead
// of throwing. It receives every tool's arguments, MCP and custom tools and nested calls included, so
// the fence never needs a list of fetcher names; the only list here is the one that opts local file
// tools out (see LOCAL_TOOLS). The first block in a session carries full teaching guidance (that
// wording reliably produced one-step self-correction); repeats get a one-liner that keeps "Do NOT retry"
// without re-injecting the full guidance text into the context the fence protects. A Pi extension
// runtime is per
// session, so that state is one flag reset on `session_start`.
//
// Rules stay host-anchored and deliberately narrow: code or prose that merely mentions the tokens
// passes. The regexes are written with character classes so this file never matches its own blocklist,
// which is what lets a fenced agent edit it; a test enforces that. Keep any rule you add equally narrow.

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export type Rule = {
  pattern: RegExp;
  why: string;
  guidance?: { full?: string; terse?: string };
};

export const BLOCKED: Rule[] = [
  { pattern: /routify[-]file[-]proxy[-]sg[.]oss-ap-southeast-1[.]aliyuncs[.]com/i, why: "observed incident host (dead relay bucket)" },
  // The relay bucket label on any documented Aliyun OSS endpoint spelling (public, dual-stack, internal,
  // accelerate) and either TLD: the fabricated shape is a family, not a single memorised host.
  { pattern: /routify[\w.-]{0,12}file[\w.-]{0,56}aliyuncs[.](com|io)/i, why: "relay bucket label (any routify-file-* form) on an Aliyun OSS endpoint, com or io TLD" },
  // Label *and* endpoint both required: the bare label is an ordinary domain, and other buckets on the
  // same endpoint are legitimate.
  {
    pattern: /sanmaohe[\w.-]{0,24}aliyuncs[.](com|io)/i,
    why: "upload-target bucket caught attempting an outbound PUT with a payload",
    guidance: {
      full: `This host is an upload endpoint caught in the wild receiving a ` +
        `model-initiated PUT of a payload; it is not a content source, and ` +
        `contacting it reports this machine's presence and network. Do NOT ` +
        `retry it and do not probe it with GET either. Complete the task ` +
        `without any outbound request to this host.`,
      terse: `Model-initiated upload endpoint. Do NOT dial it.`,
    },
  },
];

// Parked rule, kept from the opencode original but off by default: it is not a relay artifact, so it sits
// outside what this fence is for, and on a machine that is not a cloud VM nothing answers the address
// anyway. It blocks the cloud metadata surface (the link-local address, one non-link-local vendor variant,
// and the GCP hostname), which is where a cloud host serves its own temporary credentials. Numeric
// boundaries keep longer numbers (versions, concatenated addresses) out. The why-string is deliberately
// number-free: it is echoed into the tool error and would otherwise re-trip this rule. Opt it in without
// editing this file:
export const OPTIONAL: Rule[] = [
  {
    pattern: /(?:^|[^\d.])169[.]254[.]169[.]254(?:$|[^\d.])|(?:^|[^\d.])100[.]100[.]100[.]200(?:$|[^\d.])|metadata[.]google[.]internal/i,
    why: "cloud instance-metadata endpoint (temporary-credential surface; never needed by an agent task)",
    guidance: {
      full: `Cloud metadata addresses hand out the machine's temporary IAM ` +
        `credentials; reaching for one is a credential-exfiltration primitive ` +
        `and is never required to complete a coding or analysis task. Do NOT ` +
        `retry it. Continue the task without touching any metadata address.`,
      terse: `Cloud metadata endpoint (credential surface). Do NOT dial it; continue without it.`,
    },
  },
];
// Opt in to the parked rule for a session (any non-empty value), which survives an update of this file:
//   PI_BLOCK_PROXY_METADATA=1 pi
if (process.env.PI_BLOCK_PROXY_METADATA) BLOCKED.push(...OPTIONAL);

// Strings inside a call's arguments: values, array items, object keys, up to 6 container levels.
export function* strings(v: unknown, depth = 0): Generator<string> {
  if (depth > 6) return;
  if (typeof v === "string") yield v;
  else if (Array.isArray(v)) for (const x of v) yield* strings(x, depth + 1);
  else if (v && typeof v === "object")
    for (const [k, x] of Object.entries(v)) {
      yield k;
      yield* strings(x, depth + 1);
    }
}

// `rules` defaults to the live fence; pass OPTIONAL to check a parked rule.
export function findBlocked(args: unknown, rules: Rule[] = BLOCKED): Rule | null {
  for (const s of strings(args))
    for (const b of rules) if (b.pattern.test(s)) return b;
  return null;
}

const FULL_GUIDANCE =
  `This URL is a dead upload-proxy artifact from a third-party relay middlebox, not a real ` +
  `content source: it cannot be fetched and retrying leaks trace identifiers. ` +
  `Do NOT retry it. Go back to the original publisher URL and fetch that instead.`;

const TERSE_GUIDANCE =
  `Dead upload-proxy artifact from a third-party relay middlebox. Do NOT retry it. ` +
  `Fetch the original publisher URL directly.`;

// Returns the block message for a call shape (flipping `warned` so repeats stay terse), or null to allow.
export function verdict(args: unknown, warned: { first: boolean }, rules: Rule[] = BLOCKED): string | null {
  const hit = findBlocked(args, rules);
  if (!hit) return null;
  const first = !warned.first;
  warned.first = true;
  const g = hit.guidance ?? {};
  return (
    `Blocked by block-proxy-artifacts policy (${hit.why}). ` +
    (first ? (g.full ?? FULL_GUIDANCE) : (g.terse ?? TERSE_GUIDANCE))
  );
}

// Tools that cannot open a socket: an indicator sitting in their arguments is only text on disk, so
// scanning them buys no network protection and blocks ordinary file work. Every other tool is checked,
// including MCP fetchers and browser tools whose names this file cannot enumerate. Divergence from
// upstream, which scans all tools: a bash command that merely greps for a literal still trips, because
// bash is also the most common dial.
export const LOCAL_TOOLS = new Set(["read", "grep", "find", "ls", "edit", "write"]);

export default function blockProxyArtifacts(pi: ExtensionAPI): void {
  const warned = { first: false };
  pi.on("session_start", () => {
    warned.first = false;
  });
  pi.on("tool_call", (event) => {
    if (LOCAL_TOOLS.has(event.toolName)) return undefined;
    const message = verdict(event.input, warned);
    if (message) return { block: true, reason: message };
    return undefined;
  });
}
