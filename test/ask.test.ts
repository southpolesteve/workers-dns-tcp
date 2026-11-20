import assert from "node:assert/strict";
import test from "node:test";
import { decode, encode, type Packet, type RecordType } from "@portable/dns-packet";
import { createLookup } from "../src/ask.ts";
import { answerQuery } from "../src/dns.ts";

const name = "why-is-the-sky-blue.ask.example.test";
type Run = (model: string, input: { messages: { content: string }[]; max_completion_tokens: number; temperature: number }) => Promise<unknown>;

async function query(run?: Run, qname = name, type: RecordType = "TXT", extra: Packet = {}) {
  const lookup = createLookup(run ? { run } as unknown as Ai : undefined);
  const bytes = encode({ id: 53, questions: [{ name: qname, type }], ...extra });
  const reply = await answerQuery(bytes, lookup);
  assert.ok(reply);
  return decode(reply, { framing: "tcp" });
}

test("a TXT lookup runs the bound model and returns one UTF-8-safe TXT RR", async () => {
  const answer = "a".repeat(254) + "🌤️ blue sky.";
  let calls = 0;
  const reply = await query(async (model, input) => {
    calls++;
    assert.equal(model, "@cf/google/gemma-4-26b-a4b-it");
    assert.equal(input.messages.at(-1)?.content, "why is the sky blue");
    // DNS formatting instructions made Gemma return SPF records to unrelated questions.
    assert.doesNotMatch(input.messages[0]!.content, /\b(?:dns|txt|spf)\b/i);
    assert.equal(input.temperature, 0);
    assert.equal(input.max_completion_tokens, 64);
    return { choices: [{ message: { content: answer } }] };
  }, name.toUpperCase());
  assert.equal(calls, 1);
  assert.equal(reply.id, 53);
  assert.equal(reply.rcode, "NOERROR");
  assert.equal(reply.flags.aa, true);
  assert.equal(reply.answers.length, 1);
  const [record] = reply.answers;
  assert.ok(record?.type === "TXT");
  assert.equal(record.ttl, 60);
  assert.equal(record.name, name);
  assert.ok(record.data.length > 1 && record.data.every(chunk => chunk.length <= 255));
  assert.equal(record.data.map(chunk => new TextDecoder("utf-8", { fatal: true }).decode(chunk)).join(""), answer);
});

test("help, ordinary records, invalid prompts and non-TXT lookups do not consume inference", async () => {
  let calls = 0;
  const run = async () => { calls++; return {}; };
  const help = await query(run, "ask.example.test");
  assert.equal(help.answers[0]?.type, "TXT");
  assert.equal((await query(run, "example.test", "A")).answers[0]?.type, "A");
  assert.equal((await query(run, name, "A")).rcode, "REFUSED");
  assert.equal((await query(run, name, "ANY")).rcode, "REFUSED");
  assert.equal((await query(run, "bad--slug.ask.example.test")).rcode, "NXDOMAIN");
  assert.equal((await query(run, "one.two.ask.example.test")).rcode, "NXDOMAIN");
  assert.equal((await query(run, "question.ask.elsewhere.test")).rcode, "REFUSED");
  assert.equal((await query(run, name, "TXT", { opcode: "UPDATE" })).rcode, "NOTIMP");
  assert.equal(calls, 0);
  assert.equal((await query()).rcode, "NXDOMAIN");
});

test("a model error or empty answer gives SERVFAIL with the original transaction ID", async () => {
  for (const run of [async () => { throw new Error("upstream unavailable"); },
    async () => ({ choices: [{ message: { content: " " } }] })]) {
    const reply = await query(run);
    assert.equal(reply.id, 53);
    assert.equal(reply.rcode, "SERVFAIL");
    assert.equal(reply.answers.length, 0);
  }
});

test("the deployed suffix selects the question and appears in the help record", async () => {
  const prompts: string[] = [];
  const lookup = createLookup({ run: async (_model: string, input: { messages: { content: string }[] }) => {
    prompts.push(input.messages.at(-1)!.content);
    return { choices: [{ message: { content: "Four." } }] };
  } } as unknown as Ai, "Ask.Southpolesteve.Com.");
  const host = "ask.southpolesteve.com";
  for (const qname of [host, "two-plus-two." + host, "wrong.ask.example.test"]) {
    const wire = await answerQuery(encode({ questions: [{ name: qname, type: "TXT" }] }), lookup);
    assert.ok(wire);
    const result = decode(wire, { framing: "tcp" });
    if (qname.startsWith("wrong.")) assert.equal(result.rcode, "NXDOMAIN");
    else {
      const [record] = result.answers;
      assert.ok(record?.type === "TXT");
      const text = new TextDecoder().decode(record.data[0]);
      if (qname === host) assert.ok(text.includes(host));
      else assert.equal(text, "Four.");
    }
  }
  assert.deepEqual(prompts, ["two plus two"]);
});
