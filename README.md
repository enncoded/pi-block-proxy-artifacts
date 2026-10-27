# block-proxy-artifacts for Pi

A [Pi](https://github.com/earendil-works/pi) extension that blocks hallucinated file-proxy artifact
URLs, and the cloud instance-metadata surface, before any tool dials out. A blocked call never executes.

## The behavior it stops

Some models fabricate signed Aliyun OSS "file proxy" links and hand them to a fetch tool or `curl`:

```text
https://routify-file-proxy-sg.oss-ap-southeast-1.aliyuncs.com/proxy_temp_file/production/<date>/trace_<hex>/requestId_<hex>/<hash>?Expires=…&OSSAccessKeyId=…&Signature=…
```

Nobody configured that host. The shape belongs to a cheap API-relay middlebox substituting a link for an
oversized tool output, and the model remembered it from pretraining. The real service answers `403`, so
the link can never be fetched, and every attempt:

- burns an agent step, plus a retry if the model does not take the hint;
- sends the URL, this machine's IP and a timestamp to a third party;
- leaves roughly 200 tokens of call-and-error junk in the context, which every later step re-reads.

Small Qwen 3.8 Flash builds do it, and the failure class is not model-specific: anything that has
memorized the signed-URL schema can emit it. A model in that state will equally reach for
`169.254.169.254`, the link-local metadata address that hands out the machine's temporary cloud
credentials.

## What it does

On every `tool_call` the extension scans the call arguments (strings, array items, nested object values
and keys, 6 container levels) against four rules and returns `{ block: true, reason }`:

| # | Catches |
| - | ------- |
| 1 | the relay host behind the original incidents |
| 2 | the relay bucket label family (`routify-file-*`, proxy-less labels included) on any Aliyun OSS endpoint spelling, `.com` or `.io` |
| 3 | an upload-target bucket caught taking a model-initiated `PUT` (label and OSS endpoint both required) |
| 4 | the cloud metadata surface: the link-local address, one non-link-local vendor variant, and the GCP hostname |

The error text is written to end the retry loop, not just fail the call. The first block in a session
carries full teaching guidance; repeats get a one-liner that keeps "Do NOT retry" without re-injecting
~100 tokens into the context the fence protects.

The fence sits on Pi's tool pipeline and on outbound calls. A relay that genuinely replaces long outputs
with signed links still leaves those links in the transcript, so what stops here is the repeat dial.

## Install

```bash
pi install git:github.com/enncoded/pi-block-proxy-artifacts
```

Or copy the single file into your user extensions directory and let Pi discover it, which covers every
project:

```bash
mkdir -p ~/.pi/agent/extensions
curl -o ~/.pi/agent/extensions/block-proxy-artifacts.ts \
  https://raw.githubusercontent.com/enncoded/pi-block-proxy-artifacts/main/extensions/block-proxy-artifacts.ts
```

The `curl` form needs a public repo, or a token in the URL. `pi install` uses your own git credentials,
so it is the one that works while the repo is private. There is no build step: Pi loads the TypeScript
through jiti, and the only import is a type.

## Verify enforcement

An extension that fails to load fails quietly, so prove the fence is up in a new Pi session:

```bash
pi -p 'Use the bash tool to run exactly this command, then tell me in one line what happened: curl -sS -m 3 http://169.254.169.254/latest/meta-data/'
```

The call should come back blocked by the policy, with no `403` and no timeout.

## Limitations

- Substring matching over- and under-fires by choice. It over-fires on calls that merely mention an
  indicator, so a `write` or `edit` whose content contains a live URL is blocked, and so is a `grep` for
  one. This README is the single file in the repo carrying a literal indicator URL, so changing it from
  a fenced session means `git` or an external editor; a test keeps the sources and tests literal-free.
  The rules stay host-anchored, which is why a bare `routify` mention, an unrelated OSS bucket and a
  neighbor of the metadata address all pass.
- Redirects, DNS aliases and URL encodings get through. It is a guardrail against confabulation, not a
  network perimeter.
- Each block ends a same-URL retry loop in one step. The next fabrication still arrives whenever the
  model wants another long page.
- Nesting deeper than 6 argument levels is not scanned.
- Sinkholing the indicator hosts in `/etc/hosts` is not included here; see Defense in depth.

## Defense in depth

This fence sits in Pi's tool layer, which is a good place to catch a confabulated dial and a thin place
to enforce anything else. A program Pi runs can reach a host on its own, a rule set can lag a new shape,
and the model keeps inventing. Egress controls do not care what the model invented, so run both.

### nono

[nono](https://github.com/nolabs-ai/nono) runs Pi inside an OS-level sandbox: Landlock on Linux, Seatbelt
on macOS, enforced before Pi starts and outside Pi's approval and extension systems. Its network layer
filters by domain through a local proxy, so it covers whatever the process actually dials instead of what
a tool argument said it would.

```bash
nono run --profile pi --allow-domain github.com --allow-domain docs.python.org -- pi
```

`--deny-domain` works the other way, takes wildcards, and is evaluated before the allowlist. `--block-net`
gives a session no network at all. The same rules live in a profile under `~/.config/nono/profiles/`, so
the flags are optional:

```json
{ "network": { "allow_domain": ["github.com", "docs.python.org"] } }
```

Domain filtering is the useful property here: an invented relay host is not on the list, so it dies at the
socket and the trace identifiers stay home. nono's credential routes also keep API keys out of the
sandboxed process, which is the exposure the metadata half of this fence is about.

### Other agent sandboxes

Claude Code has a built-in sandbox with a domain allowlist, `sandbox.network.allowedDomains`, backed by
Seatbelt on macOS and by bubblewrap plus socat on Linux and WSL2. Same boundary, different product, which
is a reasonable signal that this bug class is not specific to one agent.

### Bare OS mechanisms

For one risky command instead of a whole session, take away the route:

```bash
bwrap --ro-bind / / --dev /dev --unshare-net -- curl -sS https://example.com
firejail --net=none -- nmap -sn 10.0.0.0/24
```

The first one was checked on this machine: `curl` inside `--unshare-net` fails to connect (exit 7). Both
are absolute, which is also the cost, since `git` and `npm` need the network. macOS has the equivalent in
Seatbelt profiles through `sandbox-exec`.

### The network layer

Sinkholing the indicator hosts in `/etc/hosts`, or blocking them in a resolver such as Pi-hole or AdGuard,
covers processes that never went through Pi. It stops the shapes you listed and nothing else, so it is a
backstop for the rules table rather than a policy of its own. An upstream proxy with an allowlist is the
same idea with wider reach, and it is what nono chains into with `--upstream-proxy`.

| Layer | Catches | Lets through |
| ----- | ------- | ------------ |
| this extension | every tool call Pi makes, MCP and nested calls included, with an error the model reads | work outside Pi's tool pipeline |
| nono domain rules | every connection from the sandboxed process tree | content a permitted host returns |
| namespace isolation | everything, by removing the route | anything that needs the network |
| hosts file or resolver | the indicators you listed | any new shape |

## Development

```bash
npm install
npm run typecheck   # tsc --noEmit against Pi's own shipped types
npm test            # node --test, TypeScript run directly, no build step
```

`npm test` needs Node 22.18+ (or 23.6+) for type stripping. One test asserts the blocklist never matches
this repo's own sources, so a pattern rewrite that leaves the fence unable to edit itself fails CI.

## License

MIT, in [LICENSE](LICENSE). The rules and the model-facing guidance text are derived from
[wtogami/qwen-block-proxy-artifacts](https://github.com/wtogami/qwen-block-proxy-artifacts) (MIT), the
opencode plugin this is ported from, which also carries the incident forensics behind them.
