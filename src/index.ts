import { answerQuery } from "./dns.ts";
import { createLookup } from "./ask.ts";

// Consume split prefixes, split bodies and multiple frames in the same read.
// Only allocate the declared body once, and await each write for backpressure.
async function connect(socket: Socket, env: Env) {
  const lookup = createLookup(env.AI);
  const reader = socket.readable.getReader();
  const writer = socket.writable.getWriter();
  let timer: ReturnType<typeof setTimeout> | null = null;
  let expired = false;
  function armDeadline() {
    clearTimeout(timer);
    timer = setTimeout(() => {
      expired = true;
      void socket.close().catch(() => {});
    }, 15_000);
  }

  const prefix = new Uint8Array(2);
  let target = prefix;
  let filled = 0;
  armDeadline();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      let offset = 0;
      while (offset < value.length) {
        const count = Math.min(target.length - filled, value.length - offset);
        target.set(value.subarray(offset, offset + count), filled);
        filled += count;
        offset += count;
        if (filled !== target.length) continue;
        filled = 0;
        if (target === prefix) {
          const length = prefix[0]! * 256 + prefix[1]!;
          if (length < 12) return;
          target = new Uint8Array(length);
        } else {
          armDeadline(); // Give a completed query its own processing deadline.
          const response = await answerQuery(target, lookup);
          if (!response) return;
          await writer.write(response);
          target = prefix;
          armDeadline(); // A partial query does not extend the connection indefinitely.
        }
      }
    }
    await writer.close();
  } catch (error) {
    if (!expired) throw error;
  } finally {
    clearTimeout(timer);
    reader.releaseLock();
    writer.releaseLock();
    await socket.close().catch(() => {});
  }
}

export default { connect } satisfies ExportedHandler<Env>;
