import assert from "node:assert/strict";
import test from "node:test";
import { decode, encode, type Packet, type RecordType } from "@portable/dns-packet";
import { createAuthority } from "../src/authority.ts";
import { answerQuery } from "../src/dns.ts";

const apex = "example.test";
const soa = {
  name: apex, type: "SOA", ttl: 300,
  data: { mname: "ns.example.test", rname: "admin.example.test", serial: 1, refresh: 60, retry: 30, expire: 3600, minimum: 30 },
} as const;
const ns = { name: apex, type: "NS", ttl: 300, data: soa.data.mname } as const;

function query(name = apex, type: RecordType = "A", fields: Packet = {}) {
  return encode({ id: 431, questions: [{ name, type }], ...fields });
}

function response(bytes: Uint8Array, lookup?: ReturnType<typeof createAuthority>) {
  const reply = answerQuery(bytes, lookup);
  assert.ok(reply);
  assert.equal(new DataView(reply.buffer, reply.byteOffset).getUint16(0), reply.length - 2);
  return decode(reply, { framing: "tcp" });
}

test("authoritative records, case preservation and unicast response flags", () => {
  const reply = response(query("WwW.Example.Test", "A", { flags: { rd: true, ad: true, cd: true } }));
  assert.equal(reply.id, 431);
  assert.equal(reply.questions[0]?.name, "WwW.Example.Test");
  assert.deepEqual(reply.flags, { aa: true, tc: false, rd: true, ra: false, ad: false, cd: true });
  assert.deepEqual(reply.answers.map(r => [r.type, "data" in r && r.data]), [
    ["CNAME", apex], ["A", "192.0.2.1"],
  ]);
  assert.equal(response(query(apex, "AAAA")).answers[0]?.type, "AAAA");
  assert.equal(response(query("www.example.test", "CNAME")).answers.length, 1);
});

test("address records accompany NS and MX answers in the additional section", () => {
  for (const [type, address] of [["NS", "192.0.2.53"], ["MX", "192.0.2.25"]] as const) {
    const result = response(query(apex, type, { additionals: [{ type: "OPT" }] }));
    assert.deepEqual(result.additionals.map(r => "data" in r ? r.data : r.type), [address, "OPT"]);
  }
});

test("NODATA and NXDOMAIN include the SOA at its negative-cache TTL", () => {
  for (const [name, rcode] of [[apex, "NOERROR"], ["absent.example.test", "NXDOMAIN"]]) {
    const result = response(query(name, "TYPE65432"));
    assert.equal(result.rcode, rcode);
    assert.equal(result.answers.length, 0);
    assert.ok(result.flags.aa);
    const [negative] = result.authorities;
    assert.ok(negative?.type === "SOA");
    assert.equal(negative.ttl, 60);
  }
});

test("a descendant makes its empty ancestors exist, including for ANY", () => {
  const lookup = createAuthority(apex, [soa, ns, { name: "leaf.branch.example.test", type: "A", data: "192.0.2.2" }]);
  assert.equal(response(query("branch.example.test", "ANY"), lookup).rcode, "NOERROR");
  assert.equal(response(query("branch.example.test"), lookup).authorities[0]?.type, "SOA");
  assert.equal(response(query(apex, "ANY")).answers.length, 1);
});

test("CNAMEs ending outside the zone, at a missing name, or in a cycle", () => {
  const lookup = createAuthority(apex, [soa, ns, ...[
    ["external", "somewhere.invalid"], ["dangling", "absent.example.test"],
    ["a", "b.example.test"], ["b", "a.example.test"],
  ].map(([name, data]) => ({ name: name + "." + apex, type: "CNAME" as const, data: data! }))]);
  const external = response(query("external.example.test"), lookup);
  assert.equal(external.answers.length, 1);
  assert.equal(external.authorities.length, 0);
  assert.equal(external.rcode, "NOERROR");
  const dangling = response(query("dangling.example.test"), lookup);
  assert.equal(dangling.rcode, "NXDOMAIN");
  assert.equal(dangling.answers[0]?.type, "CNAME");
  assert.equal(dangling.authorities[0]?.type, "SOA");
  assert.equal(response(query("a.example.test"), lookup).rcode, "SERVFAIL");
});

test("refuses foreign names, foreign classes, and zone transfers", () => {
  for (const bytes of [
    query("other.test"), query("notexample.test"), query(String.raw`fake\.example.test`),
    query(apex, "A", { questions: [{ name: apex, type: "A", class: "CH" }] }),
    query(apex, "AXFR"), query(apex, "IXFR", { authorities: [soa] }),
  ]) {
    const result = response(bytes);
    assert.equal(result.rcode, "REFUSED");
    assert.equal(result.flags.aa, false);
    assert.equal(result.answers.length, 0);
  }
});

test("EDNS version negotiation, DNSSEC OK and unknown options", () => {
  const bad = response(query(apex, "A", { additionals: [{ type: "OPT", version: 1 }] }));
  const [opt] = bad.additionals;
  assert.ok(opt?.type === "OPT");
  assert.equal(opt.extendedRcode, 1);
  assert.equal(opt.version, 0);
  assert.equal(bad.rcode, "NOERROR");
  assert.equal(bad.answers.length, 0);
  const valid = response(query(apex, "A", { additionals: [{
    type: "OPT", dnssecOk: true, options: [{ code: "OPTION65001", data: new Uint8Array(7) }],
  }] }));
  assert.equal(valid.rcode, "NOERROR");
  assert.ok(valid.additionals[0]?.type === "OPT" && valid.additionals[0].dnssecOk);
  assert.deepEqual(valid.additionals[0].options, []);
  assert.equal(response(query()).additionals.length, 0);
});

test("malformed messages get FORMERR; unsupported opcodes get NOTIMP", () => {
  const duplicateOpt = query(apex, "A", { additionals: [{ type: "OPT" }, { type: "OPT" }] });
  const malformedOpt = query(apex, "A", { additionals: [{
    type: "OPT", options: [{ code: "OPTION65001", data: new Uint8Array(0) }],
  }] });
  malformedOpt[malformedOpt.length - 1] = 3;
  for (const bytes of [
    query().subarray(0, 16), Uint8Array.from([...query(), 0]),
    query(apex, "A", { questions: [] }),
    query(apex, "A", { questions: [{ name: apex, type: "A" }, { name: apex, type: "MX" }] }),
    duplicateOpt, malformedOpt,
  ]) assert.equal(response(bytes).rcode, "FORMERR");
  assert.equal(response(query(apex, "A", { opcode: "UPDATE" })).rcode, "NOTIMP");
  assert.equal(answerQuery(new Uint8Array(11)), undefined);
  assert.equal(answerQuery(query(apex, "A", { type: "response" })), undefined);
});

test("TCP replies can exceed the advertised UDP size and preserve full RRsets", () => {
  const data = ["x".repeat(240)];
  const records = Array.from({ length: 4 }, (_, i) => ({ name: apex, type: "TXT" as const, data: [...data, String(i)] }));
  const lookup = createAuthority(apex, [soa, ns, ...records]);
  const bytes = answerQuery(query(apex, "TXT", { additionals: [{ type: "OPT", udpPayloadSize: 512 }] }), lookup)!;
  assert.ok(bytes.length > 512);
  const reply = decode(bytes, { framing: "tcp" });
  assert.equal(reply.flags.tc, false);
  assert.equal(reply.answers.length, 4);
});

test("rejects a CNAME mixed with other data and unsupported child delegations", () => {
  assert.throws(() => createAuthority(apex, [soa, ns, { name: apex, type: "CNAME", data: "other.test" }]), /CNAME/);
  assert.throws(() => createAuthority(apex, [soa, { ...ns, name: "sub.example.test" }]), /owner/);
});

test("an RRset too large for TCP yields a framed, truncated response with its question", () => {
  const text = "x".repeat(250);
  const records = Array.from({ length: 270 }, (_, i) => ({
    name: apex, type: "TXT" as const, data: [text, String(i)],
  }));
  const lookup = createAuthority(apex, [soa, ns, ...records]);
  const reply = response(query(apex, "TXT", { additionals: [{ type: "OPT" }] }), lookup);
  assert.ok(reply.flags.tc);
  assert.equal(reply.answers.length, 0);
  assert.equal(reply.questions[0]?.type, "TXT");
  assert.equal(reply.additionals[0]?.type, "OPT");
});
