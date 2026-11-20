# DNS over TCP on Cloudflare Workers

Cloudflare Workers can accept TCP connections now, so naturally someone had to bring DNS to Cloudflare.

This is an authoritative nameserver in TypeScript. The Worker's `connect(socket)` handler reads DNS queries off the wire and answers from an editable zone. An optional Workers AI binding also lets you use `dig` as an LLM client. You can talk to the Worker on your laptop, or through Spectrum after deploying. [Workers TCP announcement](https://developers.cloudflare.com/changelog/post/2026-11-19-inbound-tcp/)

## Run it locally

With Node.js 24 or later installed, run these commands from the project directory.

```sh
npm ci
npm run dev
```

Wrangler starts a raw TCP listener on `127.0.0.1:5353`. In another terminal, query the sample zone.

```console
$ dig +tcp +short @127.0.0.1 -p 5353 finally.example.test TXT
"Cloudflare has DNS now."
```

Query the A record for `www` to see an alias and its target in the same reply.

```sh
dig +tcp +norecurse @127.0.0.1 -p 5353 www.example.test A
```

Look for the `aa` flag and these two answers.

```text
www.example.test.  300  IN  CNAME  example.test.
example.test.      300  IN  A      192.0.2.1
```

```sh
dig +tcp +norecurse @127.0.0.1 -p 5353 example.test AAAA
dig +tcp +norecurse @127.0.0.1 -p 5353 _info.example.test TXT
dig +tcp +norecurse @127.0.0.1 -p 5353 absent.example.test A
```

## Ask an LLM with dig

After `npm ci`, sign in to Cloudflare with `npx wrangler login` if needed, then run `npm run dev:llm`. This starts a second local DNS listener on TCP port 5354. The Worker sends questions to Google's Gemma 4 through the remote Workers AI binding. In another terminal, try the query below. The quoted text is from a live run.

```console
$ dig +tcp +short +time=15 +tries=1 @127.0.0.1 -p 5354 why-is-the-sky-blue.ask.example.test TXT
"The sky appears blue because of Rayleigh scattering, where shorter blue wavelengths of sunlight are scattered more strongly by the Earth's atmosphere."
```

Put a question in one DNS label before `.ask.example.test`. Use up to 63 ASCII letters, digits and single hyphens between words. DNS ignores letter case, and the Worker turns hyphens into spaces. Each prompt sent directly to the Worker as a TXT query gets one model call capped at 64 output tokens. The reply is a single TXT record with a 60-second TTL. A model timeout, exhausted quota or empty answer returns SERVFAIL. Query `ask.example.test TXT` for usage without calling the model. Prompts are visible in the DNS query name, including to any resolver you send them through.

The free inference allowance comes from **Workers AI**. Cloudflare includes 10,000 neurons per account per day. Workers Free stops at that limit, while Workers Paid can incur overage. This example uses the native binding without a separate AI Gateway setup. The local demo needs no Spectrum application. A public raw TCP endpoint uses Spectrum and its separate plan requirements. [Workers AI pricing](https://developers.cloudflare.com/workers-ai/platform/pricing/) · [Gemma model](https://developers.cloudflare.com/workers-ai/models/gemma-4-26b-a4b-it/) · [Spectrum plans](https://developers.cloudflare.com/spectrum/protocols-per-plan/)

## Configure a zone

Edit [src/zone.ts](src/zone.ts). Set the origin, replace the example names and addresses, and increment the SOA serial when changing zone data. Use absolute ASCII names, with an optional final dot, and Punycode for internationalized names. The bundled records use reserved example names and addresses.

The zone supports SOA, NS, A, AAAA, CNAME, MX, TXT, CAA, PTR and SRV records. Include one apex SOA and at least one apex NS. Records with the same owner and type share a TTL. Zone initialization checks the record wire encoding, TTLs, owner boundaries and CNAME exclusivity.

The server follows in-zone aliases, includes local addresses for NS, MX and SRV targets, and returns one complete RRset for ANY. Missing names return NXDOMAIN. An existing name without the requested type returns NOERROR with an empty answer, including at empty non-terminals. Both negative responses carry the zone SOA with the smaller of its TTL and MINIMUM. Foreign zones and zone transfers receive REFUSED. The scope is a static zone with explicit owners. Wildcard synthesis, child delegations, DNSSEC signing, dynamic updates and recursion are outside that scope. [Negative caching](https://www.rfc-editor.org/rfc/rfc2308.html) · [Minimal ANY responses](https://www.rfc-editor.org/rfc/rfc8482.html)

## TCP and EDNS

The handler reassembles two-byte length-prefixed messages up to 65,535 bytes. A connection can carry multiple queries, including pipelined ones. Each response write completes before the next response is sent. Clients can half-close their write side and still read pending replies. A 15-second deadline bounds idle connections and incomplete requests. EDNS(0) queries receive an OPT response. An unsupported EDNS version receives BADVERS. TCP responses can exceed the client's advertised UDP size. [DNS over TCP](https://www.rfc-editor.org/rfc/rfc7766.html) · [EDNS(0)](https://www.rfc-editor.org/rfc/rfc6891.html)

## Verify

```sh
npm run check     # Generate types from the pinned Workers runtime and run TypeScript
npm test          # DNS wire-format and zone behavior
npm run build     # Produce a deployment bundle in dist/ with Wrangler's dry run
npm run test:tcp  # With npm run dev running, exercise real loopback TCP connections
```

## Expose the TCP endpoint

1. Set your Worker name in [wrangler.jsonc](wrangler.jsonc). For the AI demo, set `env.llm.vars.ASK_NAME` to the DNS name under which clients will ask questions. The local `dev:llm` script overrides it with `ask.example.test`. Sign in with `npx wrangler login`. Run `npm run deploy` for the static DNS server, or `npx wrangler deploy --env llm` for the AI-enabled Worker (`workers-dns-tcp-llm` by default).
2. In the same account, open **Spectrum** for a Cloudflare-authoritative zone. On Pro or Business, create a **Workers (tcp)** application. With Spectrum Enterprise, create a **TCP** application and select **Worker** as the origin.
3. Choose a hostname in that zone, select the deployed Worker, and set a single edge port, such as TCP 53 for plain DNS. Use passthrough with edge TLS termination off. The local listener port is independent of the Spectrum edge port.
4. Query the Spectrum hostname from another machine. For example, with `ASK_NAME=ask.your-domain.example` and edge port 53, run `dig +tcp +short +time=15 +tries=1 @ask.your-domain.example why-is-the-sky-blue.ask.your-domain.example TXT`. Naming the server explicitly directs the DNS connection to the Worker.

Worker origins are in public beta. Pro and Business zones without Spectrum Enterprise allow one Worker-origin app on one TCP port per zone. Free zones are ineligible. A Workers deployment alone does not provision the public TCP hostname. [Spectrum setup and plan requirements](https://developers.cloudflare.com/spectrum/how-to/route-tcp-traffic-to-a-worker/)

**Public DNS delegation requires UDP as well as TCP.** This Worker serves explicit TCP clients. To use it as the TCP side of a conventional authoritative nameserver, also provide a UDP service on port 53 at the advertised nameserver address, serving the same zone data. [DNS transport requirements](https://www.rfc-editor.org/rfc/rfc7766.html)

## License

[MIT](LICENSE)
