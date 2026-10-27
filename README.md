# block-proxy-artifacts for Pi

A [Pi](https://github.com/earendil-works/pi) extension that blocks hallucinated file-proxy artifact
URLs before any tool dials out. A blocked call never executes. This is a Pi port of the
OpenCode plugin https://github.com/wtogami/qwen-block-proxy-artifacts.

## The behavior it stops

Some models fabricate signed Aliyun OSS "file proxy" links and hand them to a fetch tool or `curl`:

```text
https://routify-file-proxy-sg.oss-ap-southeast-1.aliyuncs.com/proxy_temp_file/production/<date>/trace_<hex>/requestId_<hex>/<hash>?Expires=…&OSSAccessKeyId=…&Signature=…
```

Nobody configured that host, it was memorized from model training. Even though the server answers `403` for
a made-up link, every attempt:

- burns an agent step, plus a retry if the model does not take the hint
- sends the URL, this machine's IP, a timestamp, plus whatever else the model decides to include in the URL to a third party (perhaps API tokens as parameters)
- leaves roughly 200 tokens of call-and-error junk in the context, which every later step re-reads

This was first found in Qwen 3.8 Flash Next, but the failure class is not model-specific: anything that has
memorized the signed-URL schema can emit it. And this type of error can happen with any URL a model is trained on.

Reporting on this issue:
* https://cohere.com/blog/concerning-behaviour-popular-open-weight-ai-model
* https://www.theregister.com/ai-and-ml/2026/10/26/alibabas-qwen-ai-caught-trying-to-contact-server-in-china/5305561 

## What it does

On every network-capable tool call the extension scans the call arguments (strings,
array items, nested object values and keys, 6 container levels) against three rules and returns
`{ block: true, reason }`.

The local file tools (`read`, `grep`, `find`, `ls`, `edit`, `write`) are exempt since
they cannot open a socket.

The plugin catches 3 things:

| # | Catches | Source |
| - | ------- | ------ |
| 1 | the exact host in the original incidents | [upstream incident log](https://github.com/wtogami/qwen-block-proxy-artifacts/blob/master/README.md) |
| 2 | near-variants of the URL: other hosts starting with the same `routify-file-` label, with or without the `-proxy-` part, on any Aliyun OSS domain (`.com` or `.io` ending). | [how upstream picked these shapes](https://github.com/wtogami/qwen-block-proxy-artifacts/blob/master/SURGERY.md) |
| 3 | the `sanmaohe…` bucket, caught attempting an upload (a `PUT`) from the model. matched as an Aliyun OSS hostname | [Cohere report](https://cohere.com/blog/concerning-behaviour-popular-open-weight-ai-model), [packet capture notes](https://github.com/wtogami/qwen-block-proxy-artifacts/blob/master/COHERE-2026-10-26.md) |

Upstream also ships a fourth rule for the link-local cloud metadata address,
the place a cloud host serves its own temporary credentials
([Cohere report](https://cohere.com/blog/concerning-behaviour-popular-open-weight-ai-model),
[AWS instance metadata](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)).
I've chosen to disable it for this port. To fence it anyway, run with `PI_BLOCK_PROXY_METADATA=1` set in the
environment; the rule list in `extensions/block-proxy-artifacts.ts` stays untouched, so an update does not
undo your choice.

This aims to stop offending tool call as well as the resulting time-consuming retry loops. The first block
carries full teaching guidance. Repeat attemps result in a one-liner that keeps "Do NOT retry" without re-injecting
the full guidance into the context again.

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
pi -p 'Use the bash tool to run exactly this command, then tell me in one line what happened: curl -sS -m 5 https://routify-file-proxy-sg.oss-ap-southeast-1.aliyuncs.com/'
```

The call should come back blocked by the policy, with no `403` and no timeout.

## Limitations

- Any network-capable tool call containing a blocked URL is blocked, even when it is not the URL being
  dialed. For example, a `bash` call containing the URL. That is deliberate: those tools could
  connect regardless. The local file tools listed under [What it does](#what-it-does) are exempt, so you
  can read and edit any file, even one containing a blocked URL. And the rules look for the blocked
  hostname itself, not any single part of it, so a call mentioning the word `routify` (from the Aliyun URLs)
  or connecting to an ordinary Aliyun storage bucket with a different name is not blocked.
- Redirects, DNS aliases and URL encodings get through since this isn't a network level block.
- The block message tells the model not to retry, so it ends the retry loop for a hallucinated Aliyun
  URL in one step. It does not stop the model from inventing a new one the next time it wants to fetch
  a long page.
- Nesting deeper than 6 argument levels is not scanned.
- This extension only blocks calls made through Pi. For ways to block these hosts more thoroughly, see
  [Defense in depth](#defense-in-depth).

## Defense in depth

While this does resolve the issue within Pi, it only does so by monitoring and blocking relevant tool calls. 
Deeper blocking is worthwhile here, especially if you use other agents besides Pi.
As such, this plugin is best paired with an agent sandbox or a network level host block.

The options below block hosts at the network level, no matter how a program tried to reach them. Use both together.

How the layers stack up:

| Layer | Catches | Lets through |
| ----- | ------- | ------------ |
| this extension | every network-capable tool call Pi makes, MCP and nested calls included, with an error the model reads | work outside Pi's tool pipeline, and the local file tools |
| nono domain rules | every connection from the sandboxed process tree | content a permitted host returns |
| hosts file or resolver | the hosts you list, or a wider pattern where the resolver supports one | any host you did not list |

<details>
<summary><h3>nono</h3></summary>

[nono](https://github.com/nolabs-ai/nono) runs agents inside an OS-level sandbox (Landlock on Linux, Seatbelt
on macOS), enforced before your agents start and operate outside their approval and extension systems. Its network
layer filters by domain through a local proxy, so it covers the actual network communication instead of the tool call
arguments.

```bash
nono run --profile pi --allow-domain github.com --allow-domain docs.python.org -- pi
```

`--deny-domain` works the other way, takes wildcards, and is evaluated before the allowlist. `--block-net`
gives a session no network at all. The same rules live in a profile under `~/.config/nono/profiles/`, so
the flags are optional:

```json
{ "network": { "allow_domain": ["github.com", "docs.python.org"] } }
```

Filtering by domain is the useful property here: a made-up Aliyun URL is not a domain you allowed, so
the connection fails before anything is sent, and the IDs built into the URL never leave your machine. 

**Docs:** [nono.sh/docs](https://nono.sh/docs)

</details>

<details>
<summary><h3>The network layer</h3></summary>

Pointing the fake hostnames at a dead address in `/etc/hosts`, or blocking them in a resolver such as
Pi-hole or AdGuard, covers programs that never go through Pi. `/etc/hosts` needs one entry per hostname,
while resolvers take wildcards and regex, so you can write your own broader patterns instead of mirroring
the rules table. Either way, anything you did not put on the list gets through, so this layer only helps
as much as the list you maintain. An upstream proxy with an allowlist is the same idea with wider reach,
and it is what nono chains into with `--upstream-proxy`.

**Docs:** [Pi-hole](https://docs.pi-hole.net/) · [AdGuard Home](https://adguard.com/adguard-home/overview.html)

</details>

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
