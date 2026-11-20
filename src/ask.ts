import type { Packet, RecordType } from "@portable/dns-packet";
import { authority, origin } from "./zone.ts";

const model = "@cf/google/gemma-4-26b-a4b-it";

// One TXT RR can contain several character-strings of at most 255 octets.
// encodeInto stops at a UTF-8 character boundary, even for a four-byte emoji.
function txtAnswer(name: string, text: string): Packet {
  const encoder = new TextEncoder();
  const data: Uint8Array[] = [];
  while (text.length) {
    const chunk = new Uint8Array(255);
    const { read, written } = encoder.encodeInto(text, chunk);
    data.push(chunk.subarray(0, written));
    text = text.slice(read);
  }
  return { flags: { aa: true }, answers: [{ name, type: "TXT", ttl: 60, data }] };
}

async function ask(ai: Ai, name: string, question: string): Promise<Packet> {
  try {
    const result = await ai.run(model, {
      messages: [
        { role: "system", content: "Answer in one short plain-text sentence. The answer goes in a DNS TXT record." },
        { role: "user", content: question },
      ],
      chat_template_kwargs: { enable_thinking: false },
      max_completion_tokens: 64,
    }, { signal: AbortSignal.timeout(12_000) });
    const text = result.choices[0]?.message.content?.trim();
    if (text) return txtAnswer(name, text.replace(/\s+/g, " "));
  } catch {
    // Quota, timeout and upstream errors are transient DNS failures.
  }
  return { rcode: "SERVFAIL" };
}

export function createLookup(ai?: Ai, askName = `ask.${origin}`) {
  if (!ai) return authority;
  askName = askName.toLowerCase().replace(/\.$/, "");
  const suffix = `.${askName}`;
  return (name: string, type: RecordType): Packet | Promise<Packet> => {
    if (name === askName && type === "TXT") {
      return txtAnswer(name, `Ask TXT <question-with-hyphens>.${askName}. Use one label, up to 63 ASCII characters.`);
    }
    if (name !== askName && !name.endsWith(suffix)) return authority(name, type);
    const label = name.slice(0, -suffix.length);
    if (name !== askName && !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(label)) return authority(name, type);
    // Only an explicit TXT question runs a model, including when clients probe ANY.
    if (type !== "TXT") return { rcode: "REFUSED" };
    return ask(ai, name, label.replaceAll("-", " "));
  };
}
