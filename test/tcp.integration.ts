// Start npm run dev before running npm run test:tcp.
import assert from "node:assert/strict";
import { once } from "node:events";
import { connect, type Socket } from "node:net";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { decode, encode, type RecordType } from "@portable/dns-packet";

async function open() {
  const socket = connect({ host: "127.0.0.1", port: 5353 });
  await once(socket, "connect");
  return socket;
}

function frame(id: number, type: RecordType) {
  return encode({ id, questions: [{ name: "example.test", type }] }, { framing: "tcp" });
}

async function* readReplies(socket: Socket) {
  let buffered = Buffer.alloc(0);
  for await (const chunk of socket) {
    buffered = Buffer.concat([buffered, chunk]);
    while (buffered.length >= 2) {
      const size = buffered.readUInt16BE(0);
      if (buffered.length < size + 2) break;
      yield decode(buffered.subarray(2, size + 2));
      buffered = buffered.subarray(size + 2);
    }
  }
  assert.equal(buffered.length, 0, "partial response at EOF");
}

test("Wrangler returns every pipelined reply across split reads and a client half-close", { timeout: 5000 }, async t => {
  const socket = await open();
  t.after(() => socket.destroy());
  const replies = Array.fromAsync(readReplies(socket));
  const first = frame(11, "A");
  socket.write(first.subarray(0, 1));
  await delay(30);
  socket.write(first.subarray(1, 8));
  await delay(30);
  socket.end(Buffer.concat([first.subarray(8), frame(22, "AAAA"), frame(33, "SOA")]));
  assert.deepEqual((await replies).map(r => [r.id, r.answers[0]?.type]), [[11, "A"], [22, "AAAA"], [33, "SOA"]]);
});

test("a client can wait for a reply, then reuse the connection", { timeout: 5000 }, async t => {
  const socket = await open();
  t.after(() => socket.destroy());
  const replies = readReplies(socket);
  socket.write(frame(71, "NS"));
  assert.equal((await replies.next()).value?.id, 71);
  socket.end(frame(72, "MX"));
  assert.deepEqual((await Array.fromAsync(replies)).map(r => [r.id, r.answers[0]?.type]), [[72, "MX"]]);
});

test("maximum-length query followed by an incomplete frame at EOF", { timeout: 5000 }, async t => {
  const socket = await open();
  t.after(() => socket.destroy());
  function paddedQuery(length: number) {
    return encode({
      id: 57, questions: [{ name: "example.test", type: "A" }],
      additionals: [{ type: "OPT", options: [{ code: "PADDING", length }] }],
    }, { framing: "tcp" });
  }
  const full = paddedQuery(65537 - paddedQuery(0).length);
  assert.equal(full.length - 2, 65535);
  socket.end(Buffer.concat([full, frame(58, "NS").subarray(0, 7)]));
  const replies = await Array.fromAsync(readReplies(socket));
  assert.deepEqual(replies.map(r => [r.id, r.rcode]), [[57, "NOERROR"]]);
});

test("the Worker closes idle connections with an unfinished frame", { timeout: 22000 }, async t => {
  const socket = await open();
  t.after(() => socket.destroy());
  const closed = once(socket, "close");
  const start = performance.now();
  socket.write(frame(3, "A").subarray(0, 5));
  await closed;
  assert.ok(performance.now() - start >= 14_000);
});
