import { encode, type OptRecord, type Packet, type Question, type RecordType } from "@portable/dns-packet";
import { authority } from "./zone.ts";

const queryTypes = new Map<number, RecordType>([
  [1, "A"], [2, "NS"], [5, "CNAME"], [6, "SOA"], [12, "PTR"], [15, "MX"],
  [16, "TXT"], [28, "AAAA"], [33, "SRV"], [251, "IXFR"], [252, "AXFR"],
  [255, "ANY"], [257, "CAA"],
]);

class FormatError extends Error {}

// Keep arbitrary label octets distinct from label separators. Only ASCII letters
// participate in DNS case folding (RFC 4343).
function readName(bytes: Uint8Array, start: number) {
  const labels: string[] = [];
  let offset = start;
  let ceiling = start;
  let next: number | undefined;
  let length = 1;
  let jumps = 0;

  for (;;) {
    const size = bytes[offset++];
    if (size === undefined) throw new FormatError();
    if (size === 0) return { name: labels.join(".") || ".", next: next ?? offset };
    if ((size & 0xc0) === 0xc0) {
      const low = bytes[offset++];
      if (low === undefined) throw new FormatError();
      const target = ((size & 0x3f) << 8) | low;
      if (target < 12 || target >= ceiling || ++jumps > 128) throw new FormatError();
      next ??= offset;
      offset = ceiling = target;
      continue;
    }
    length += 1 + size;
    if (size > 63 || length > 255 || offset + size > bytes.length) throw new FormatError();
    let label = "";
    for (const octet of bytes.subarray(offset, offset + size)) {
      const char = String.fromCharCode(octet);
      label += /^[a-zA-Z0-9_-]$/.test(char) ? char : "\\" + String(octet).padStart(3, "0");
    }
    labels.push(label);
    offset += size;
  }
}

function readRecordHeader(bytes: Uint8Array, view: DataView, offset: number) {
  const header = readName(bytes, offset).next;
  if (header + 10 > bytes.length) throw new FormatError();
  const type = view.getUint16(header);
  const data = header + 10;
  const end = data + view.getUint16(header + 8);
  if (end > bytes.length) throw new FormatError();
  return { type, header, data, end };
}

function checkOptionLengths(view: DataView, offset: number, end: number) {
  while (offset < end) {
    if (offset + 4 > end) throw new FormatError();
    offset += 4 + view.getUint16(offset + 2);
    if (offset > end) throw new FormatError();
  }
}

function frameReply(packet: Packet, opt: OptRecord | undefined) {
  let wire = encode(packet, { compress: true });
  if (wire.length > 65535) {
    // Drop optional address records first. Keep the OPT for EDNS clients.
    packet.additionals = opt ? [opt] : [];
    wire = encode(packet, { compress: true });
    if (wire.length > 65535) {
      // A required RRset that exceeds even the TCP limit must stay atomic.
      return encode({
        ...packet, flags: { ...packet.flags, tc: true }, answers: [], authorities: [],
      }, { framing: "tcp" });
    }
  }
  const frame = new Uint8Array(2 + wire.length);
  new DataView(frame.buffer).setUint16(0, wire.length);
  frame.set(wire, 2);
  return frame;
}

type Lookup = (name: string, type: RecordType) => Packet | Promise<Packet>;
/** Takes one unframed query. Undefined tells the caller to close without a reply. */
export function answerQuery(bytes: Uint8Array, lookup?: typeof authority): Uint8Array | undefined;
export function answerQuery(bytes: Uint8Array, lookup: Lookup): Uint8Array | Promise<Uint8Array> | undefined;
export function answerQuery(bytes: Uint8Array, lookup: Lookup = authority): Uint8Array | Promise<Uint8Array> | undefined {
  if (bytes.length < 12) return;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const id = view.getUint16(0);
  const bits = view.getUint16(2);
  const opcode = (bits >>> 11) & 15;
  if ((bits & 0x8000) || (opcode === 6 && id === 0)) return;

  let question: Question | undefined;
  let opt: OptRecord | undefined;
  function reply(result: Packet) {
    return frameReply({
      ...result, id, type: "response", opcode: `OPCODE${opcode}`,
      flags: { ...result.flags, rd: Boolean(bits & 0x100), cd: Boolean(bits & 0x10) },
      questions: question ? [question] : [],
      additionals: opt ? [...(result.additionals ?? []), opt] : result.additionals,
    }, opt);
  }

  if (opcode !== 0) return reply({ rcode: "NOTIMP" });
  if (view.getUint16(4) !== 1 || view.getUint16(6) !== 0) {
    return reply({ rcode: "FORMERR" });
  }

  try {
    const { name, next } = readName(bytes, 12);
    if (next + 4 > bytes.length) throw new FormatError();
    const code = view.getUint16(next);
    const qclass = view.getUint16(next + 2);
    const type = queryTypes.get(code) ?? `TYPE${code}`;
    question = { name, type, class: `CLASS${qclass}` };
    let offset = next + 4;
    const authorityCount = view.getUint16(8);
    if (authorityCount > 0) {
      // An IXFR query can include the client's SOA in its authority section.
      if (type !== "IXFR" || authorityCount !== 1) throw new FormatError();
      const rr = readRecordHeader(bytes, view, offset);
      if (rr.type !== 6) throw new FormatError();
      offset = rr.end;
    }
    let badVersion = false;
    let signed = false;
    const additionalCount = view.getUint16(10);
    for (let i = 0; i < additionalCount; i++) {
      const rr = readRecordHeader(bytes, view, offset);
      if (rr.type === 41) {
        if (opt) throw new FormatError();
        opt = { type: "OPT", udpPayloadSize: 1232, dnssecOk: Boolean(view.getUint16(rr.header + 6) & 0x8000) };
        if (bytes[offset] !== 0) throw new FormatError();
        badVersion = bytes[rr.header + 5] !== 0;
        if (!badVersion) checkOptionLengths(view, rr.data, rr.end);
      }
      if (rr.type === 250 || rr.type === 24) signed = true;
      offset = rr.end;
    }
    if (offset !== bytes.length) throw new FormatError();
    if (badVersion && opt) {
      opt.extendedRcode = 1; // BADVERS = (1 << 4) | NOERROR
      return reply({});
    }
    if (signed || (qclass !== 1 && qclass !== 255)) return reply({ rcode: "REFUSED" });
    const result = lookup(name.toLowerCase(), type);
    return result instanceof Promise ? result.then(reply) : reply(result);
  } catch (error) {
    if (error instanceof FormatError) return reply({ rcode: "FORMERR" });
    throw error;
  }
}
