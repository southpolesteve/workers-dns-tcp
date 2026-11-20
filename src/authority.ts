import {
  encode, type Packet, type RecordType, type ResourceRecord,
} from "@portable/dns-packet";

type ZoneRecord = Extract<ResourceRecord, {
  type: "SOA" | "NS" | "A" | "AAAA" | "CNAME" | "MX" | "TXT" | "CAA" | "SRV" | "PTR";
}>;

function zoneName(name: string): string {
  const key = name.replace(/\.$/, "");
  if (!/^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$/.test(key)) {
    throw new Error(`Expected an absolute ASCII zone name, got "${name}"`);
  }
  return key.toLowerCase();
}

export function createAuthority(origin: string, records: readonly ZoneRecord[]) {
  const apex = zoneName(origin);
  const withinZone = (name: string) => name === apex || name.endsWith(`.${apex}`);
  const nodes = new Map<string, Map<RecordType, ZoneRecord[]>>();
  const soa = records.find(record => record.type === "SOA");
  if (!soa || !records.some(record => record.type === "NS")) {
    throw new Error("A zone requires an apex SOA and at least one NS");
  }

  for (const record of records) {
    const owner = zoneName(record.name);
    if (!withinZone(owner) || (["SOA", "NS"].includes(record.type) && owner !== apex)) {
      throw new Error(`Invalid owner for ${record.type}: ${owner}`);
    }
    if (record.type === "CNAME" || record.type === "NS") zoneName(record.data);
    const ttl = record.ttl ?? 0;
    if (!Number.isInteger(ttl) || ttl < 0 || ttl > 0x7fffffff || (record.class ?? "IN") !== "IN" || record.flush) {
      throw new Error(`Invalid unicast IN record at ${owner}`);
    }
    encode({ answers: [record] }, { framing: "tcp" }); // Validate RDATA before serving.
    // Ancestors with only descendants exist too (empty non-terminals).
    for (let name = owner; ; name = name.slice(name.indexOf(".") + 1)) {
      if (!nodes.has(name)) nodes.set(name, new Map());
      if (name === apex) break;
    }

    const sets = nodes.get(owner)!;
    if ((record.type === "CNAME" && sets.size > 0) || sets.has("CNAME")) {
      throw new Error(`A CNAME must be the only record at ${owner}`);
    }
    const set = sets.get(record.type) ?? [];
    if (set.length && (record.type === "SOA" || (set[0]!.ttl ?? 0) !== ttl)) {
      throw new Error(`Duplicate SOA or inconsistent RRset TTL at ${owner}`);
    }
    set.push(record);
    sets.set(record.type, set);
  }

  const negative = [{ ...soa, ttl: Math.min(soa.ttl ?? 0, soa.data.minimum) }];
  function addressesFor(records: ZoneRecord[]) {
    const additional = new Set<ZoneRecord>();
    for (const record of records) {
      let target: string;
      switch (record.type) {
        case "NS": target = record.data; break;
        case "MX": target = record.data.exchange; break;
        case "SRV": target = record.data.target; break;
        default: continue;
      }
      const sets = nodes.get(target.replace(/\.$/, "").toLowerCase());
      for (const type of ["A", "AAAA"] as const) {
        for (const address of sets?.get(type) ?? []) additional.add(address);
      }
    }
    return [...additional];
  }
  return function lookup(name: string, type: RecordType): Packet {
    if (!withinZone(name) || type === "AXFR" || type === "IXFR") return { rcode: "REFUSED" };
    const answers: ZoneRecord[] = [];
    const flags = { aa: true };
    const seen = new Set<string>();

    while (withinZone(name)) {
      const sets = nodes.get(name);
      if (!sets) return { flags, rcode: "NXDOMAIN", answers, authorities: negative };
      // RFC 8482 permits one complete RRset for ANY.
      const match = type === "ANY" ? sets.values().next().value : sets.get(type);
      if (match) return { flags, answers: answers.concat(match), additionals: addressesFor(match) };
      const alias = sets.get("CNAME")?.[0];
      if (alias?.type !== "CNAME") return { flags, answers, authorities: negative };
      if (seen.has(name) || seen.size >= 16) return { rcode: "SERVFAIL" };
      seen.add(name);
      answers.push(alias);
      name = zoneName(alias.data);
    }
    return { flags, answers }; // The target belongs to another authority.
  };
}
