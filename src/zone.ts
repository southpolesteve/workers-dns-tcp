import type { ResourceRecord } from "@portable/dns-packet";
import { createAuthority } from "./authority.ts";

// Owners and targets are absolute DNS names. Use ASCII (Punycode for IDNs).
const origin = "example.test";
const ns = `ns1.${origin}`;
const ttl = 300;

const records = [
  {
    name: origin, type: "SOA", ttl,
    data: {
      mname: ns, rname: `hostmaster.${origin}`, serial: 2026112002,
      refresh: 3600, retry: 600, expire: 604800, minimum: 60,
    },
  },
  { name: origin, type: "NS", ttl, data: ns },
  { name: ns, type: "A", ttl, data: "192.0.2.53" },
  { name: origin, type: "A", ttl, data: "192.0.2.1" },
  { name: origin, type: "AAAA", ttl, data: "2001:db8::1" },
  { name: `www.${origin}`, type: "CNAME", ttl, data: origin },
  { name: origin, type: "MX", ttl, data: { preference: 10, exchange: `mail.${origin}` } },
  { name: `mail.${origin}`, type: "A", ttl, data: "192.0.2.25" },
  { name: `_info.${origin}`, type: "TXT", ttl, data: ["DNS over TCP on Cloudflare Workers"] },
  { name: `finally.${origin}`, type: "TXT", ttl, data: ["Cloudflare has DNS now."] },
] satisfies ResourceRecord[];

export const authority = createAuthority(origin, records);
