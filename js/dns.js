/*
 * dns.js — DNS message model, wire-format encoder and packet builders.
 *
 * Every DNS packet shown in the visualizer is a real message object that is
 * encoded to RFC 1035 wire format (with name compression), so students can
 * inspect genuine bytes in the packet inspector.
 */
(function () {
  'use strict';
  const DV = (window.DV = window.DV || {});

  const TYPES = {
    A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33,
    OPT: 41, DS: 43, RRSIG: 46, NSEC: 47, DNSKEY: 48, NSEC3: 50, SVCB: 64,
    HTTPS: 65, ANY: 255, CAA: 257, AXFR: 252, IXFR: 251,
  };
  const RCODES = { NOERROR: 0, FORMERR: 1, SERVFAIL: 2, NXDOMAIN: 3, NOTIMP: 4, REFUSED: 5 };
  const OPCODES = { QUERY: 0, NOTIFY: 4, UPDATE: 5 };
  // Types whose RDATA names may be compressed (RFC 3597 §4).
  const COMPRESSIBLE = { NS: 1, CNAME: 1, PTR: 1, MX: 1, SOA: 1 };

  /* ---------- small helpers ---------- */
  const enc = new TextEncoder();
  const utf8 = (s) => Array.from(enc.encode(s));
  const hex2 = (n) => n.toString(16).padStart(2, '0');
  const hex4 = (n) => '0x' + n.toString(16).padStart(4, '0');
  const fqdn = (n) => (n.endsWith('.') ? n : n + '.');
  const bare = (n) => (n === '.' ? '.' : n.replace(/\.$/, ''));

  function hexBytes(s) {
    const out = [];
    s = s.replace(/[^0-9a-f]/gi, '');
    for (let i = 0; i + 1 < s.length; i += 2) out.push(parseInt(s.substr(i, 2), 16));
    return out;
  }
  function b64Bytes(s) {
    try {
      const bin = atob(s.replace(/\s+/g, ''));
      return Array.from(bin, (c) => c.charCodeAt(0));
    } catch (e) {
      return utf8(s);
    }
  }
  function b32hexBytes(s) {
    const alpha = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
    let bits = 0, val = 0;
    const out = [];
    for (const ch of s.toUpperCase()) {
      const v = alpha.indexOf(ch);
      if (v < 0) continue;
      val = (val << 5) | v;
      bits += 5;
      if (bits >= 8) {
        out.push((val >> (bits - 8)) & 255);
        bits -= 8;
      }
    }
    return out;
  }
  function dnssecTime(s) {
    // YYYYMMDDHHmmSS -> seconds since epoch
    const m = /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)$/.exec(s);
    if (!m) return +s || 0;
    return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) / 1000;
  }
  function typeBitmap(types) {
    const nums = types.map((t) => TYPES[t] ?? +t).filter((n) => !isNaN(n)).sort((a, b) => a - b);
    const windows = {};
    for (const n of nums) {
      const w = n >> 8;
      (windows[w] = windows[w] || []).push(n & 255);
    }
    const out = [];
    for (const w of Object.keys(windows).map(Number).sort((a, b) => a - b)) {
      const low = windows[w];
      const len = (Math.max(...low) >> 3) + 1;
      const bm = new Array(len).fill(0);
      for (const b of low) bm[b >> 3] |= 0x80 >> (b & 7);
      out.push(w, len, ...bm);
    }
    return out;
  }

  /* ---------- IP address helpers ---------- */
  function ipv4Bytes(s) {
    return s.split('.').map((n) => parseInt(n, 10) & 255);
  }
  function ipv6Expand(s) {
    // supports trailing embedded IPv4 (e.g. 64:ff9b::203.0.113.10)
    let v4tail = null;
    const m = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
    if (m) {
      const b = ipv4Bytes(m[1]);
      v4tail = [hex2(b[0]) + hex2(b[1]), hex2(b[2]) + hex2(b[3])];
      s = s.slice(0, -m[1].length) + '0:0';
    }
    const parts = s.split('::');
    const h = parts[0] ? parts[0].split(':') : [];
    const t = parts.length > 1 ? (parts[1] ? parts[1].split(':') : []) : null;
    let groups = t === null ? h : [...h, ...new Array(8 - h.length - t.length).fill('0'), ...t];
    groups = groups.map((g) => g.padStart(4, '0').toLowerCase());
    if (v4tail) groups.splice(6, 2, ...v4tail);
    return groups;
  }
  function ipv6Bytes(s) {
    const out = [];
    ipv6Expand(s).forEach((g) => {
      const v = parseInt(g, 16);
      out.push(v >> 8, v & 255);
    });
    return out;
  }
  function ipv6Compress(groups) {
    const g = groups.map((x) => x.replace(/^0+(?=.)/, ''));
    let best = -1, bestLen = 0;
    for (let i = 0; i < 8; ) {
      if (g[i] === '0') {
        let j = i;
        while (j < 8 && g[j] === '0') j++;
        if (j - i > bestLen && j - i > 1) { best = i; bestLen = j - i; }
        i = j;
      } else i++;
    }
    if (best < 0) return g.join(':');
    return g.slice(0, best).join(':') + '::' + g.slice(best + bestLen).join(':');
  }
  const reverse4 = (ip) => ip.split('.').reverse().join('.') + '.in-addr.arpa.';
  const reverse6 = (ip) => ipv6Expand(ip).join('').split('').reverse().join('.') + '.ip6.arpa.';
  function embed64(prefix, v4) {
    const b = ipv4Bytes(v4);
    const g = ipv6Expand(prefix + '0:0').slice(0, 6);
    g.push(hex2(b[0]) + hex2(b[1]), hex2(b[2]) + hex2(b[3]));
    return ipv6Compress(g);
  }

  /* ---------- wire encoder ---------- */
  class Writer {
    constructor(base) {
      this.b = [];
      this.segs = [];
      this.names = {};
      this.base = base || 0;
    }
    get pos() { return this.b.length; }
    u8(v) { this.b.push(v & 255); }
    u16(v) { this.b.push((v >> 8) & 255, v & 255); }
    u32(v) { this.u16((v >>> 16) & 0xffff); this.u16(v & 0xffff); }
    bytes(a) { for (const x of a) this.b.push(x & 255); }
    seg(label, group, fn) {
      const s = this.pos;
      fn();
      this.segs.push({ start: s, end: this.pos, label, group });
    }
    name(n, compress) {
      n = bare(n);
      const labels = n && n !== '.' ? n.split('.') : [];
      for (let i = 0; i < labels.length; i++) {
        const suffix = labels.slice(i).join('.').toLowerCase();
        if (compress && this.names[suffix] !== undefined) {
          this.u16(0xc000 | this.names[suffix]);
          return;
        }
        const off = this.pos - this.base;
        if (off < 0x3fff && this.names[suffix] === undefined) this.names[suffix] = off;
        const lb = utf8(labels[i]).slice(0, 63);
        this.u8(lb.length);
        this.bytes(lb);
      }
      this.u8(0);
    }
  }

  function parseTxt(d) {
    const out = [];
    const re = /"((?:[^"\\]|\\.)*)"|(\S+)/g;
    let m;
    while ((m = re.exec(d))) out.push(m[1] !== undefined ? m[1] : m[2]);
    return out;
  }

  function encRdata(w, rr) {
    const d = rr.data;
    const p = d.split(/\s+/);
    switch (rr.type) {
      case 'A': w.bytes(ipv4Bytes(d)); break;
      case 'AAAA': w.bytes(ipv6Bytes(d)); break;
      case 'NS': case 'CNAME': case 'PTR': w.name(d, true); break;
      case 'MX': w.u16(+p[0]); w.name(p[1], true); break;
      case 'TXT':
        for (const s of parseTxt(d)) {
          // strings longer than 255 bytes are split into multiple character-strings
          const b = utf8(s);
          for (let i = 0; i < b.length || i === 0; i += 255) {
            const c = b.slice(i, i + 255);
            w.u8(c.length); w.bytes(c);
            if (!b.length) break;
          }
        }
        break;
      case 'SOA':
        w.name(p[0], true); w.name(p[1], true);
        for (let i = 2; i < 7; i++) w.u32(+p[i]);
        break;
      case 'SRV': w.u16(+p[0]); w.u16(+p[1]); w.u16(+p[2]); w.name(p[3], false); break;
      case 'CAA': {
        const m = /^(\d+)\s+(\S+)\s+"?(.*?)"?$/.exec(d);
        const tag = utf8(m[2]);
        w.u8(+m[1]); w.u8(tag.length); w.bytes(tag); w.bytes(utf8(m[3]));
        break;
      }
      case 'DS': w.u16(+p[0]); w.u8(+p[1]); w.u8(+p[2]); w.bytes(hexBytes(p.slice(3).join(''))); break;
      case 'DNSKEY': w.u16(+p[0]); w.u8(+p[1]); w.u8(+p[2]); w.bytes(b64Bytes(p.slice(3).join(''))); break;
      case 'RRSIG':
        w.u16(TYPES[p[0]] || 0); w.u8(+p[1]); w.u8(+p[2]); w.u32(+p[3]);
        w.u32(dnssecTime(p[4])); w.u32(dnssecTime(p[5])); w.u16(+p[6]);
        w.name(p[7], false); w.bytes(b64Bytes(p.slice(8).join('')));
        break;
      case 'NSEC': w.name(p[0], false); w.bytes(typeBitmap(p.slice(1))); break;
      case 'NSEC3': {
        w.u8(+p[0]); w.u8(+p[1]); w.u16(+p[2]);
        const salt = p[3] === '-' ? [] : hexBytes(p[3]);
        w.u8(salt.length); w.bytes(salt);
        const h = b32hexBytes(p[4]);
        w.u8(h.length); w.bytes(h);
        w.bytes(typeBitmap(p.slice(5)));
        break;
      }
      case 'SVCB': case 'HTTPS': {
        const KEYS = { mandatory: 0, alpn: 1, 'no-default-alpn': 2, port: 3, ipv4hint: 4, ech: 5, ipv6hint: 6 };
        w.u16(+p[0]);
        w.name(p[1] === '.' ? '' : p[1], false);
        const params = p.slice(2).map((kv) => {
          const [k, v = ''] = kv.split('=');
          return { k: KEYS[k] ?? 65535, name: k, v };
        }).sort((a, b) => a.k - b.k);
        for (const prm of params) {
          let val = [];
          if (prm.name === 'alpn') for (const id of prm.v.split(',')) { const b = utf8(id); val.push(b.length, ...b); }
          else if (prm.name === 'port') val = [(+prm.v >> 8) & 255, +prm.v & 255];
          else if (prm.name === 'ipv4hint') prm.v.split(',').forEach((ip) => val.push(...ipv4Bytes(ip)));
          else if (prm.name === 'ipv6hint') prm.v.split(',').forEach((ip) => val.push(...ipv6Bytes(ip)));
          else if (prm.name === 'ech') val = b64Bytes(prm.v);
          else val = utf8(prm.v);
          w.u16(prm.k); w.u16(val.length); w.bytes(val);
        }
        break;
      }
      default: w.bytes(utf8(d));
    }
  }

  const SEC_NAMES = { an: 'Answer', ns: 'Authority', ar: 'Additional' };

  function encRR(w, rr, sec) {
    const S = SEC_NAMES[sec];
    w.seg(`${S} · owner name ${rr.name}`, sec, () => w.name(rr.name, true));
    w.seg(`${S} · TYPE ${rr.type} (${TYPES[rr.type]})`, sec, () => w.u16(TYPES[rr.type] || 0));
    w.seg(`${S} · CLASS IN (1)`, sec, () => w.u16(1));
    w.seg(`${S} · TTL ${rr.ttl} s`, sec, () => w.u32(rr.ttl));
    const lenPos = w.pos;
    w.u16(0);
    const start = w.pos;
    const compress = !!COMPRESSIBLE[rr.type];
    const saveNames = w.names;
    if (!compress) w.names = Object.assign({}, saveNames);
    encRdata(w, rr);
    if (!compress) w.names = saveNames;
    const len = w.pos - start;
    w.b[lenPos] = len >> 8;
    w.b[lenPos + 1] = len & 255;
    w.segs.push({ start: lenPos, end: start, label: `${S} · RDLENGTH ${len}`, group: sec });
    w.segs.push({ start, end: w.pos, label: `${S} · RDATA ${rr.type} ${rr.data}`, group: sec });
  }

  function flagsWord(m) {
    return (
      ((m.qr ? 1 : 0) << 15) | ((OPCODES[m.opcode] || 0) << 11) | ((m.aa ? 1 : 0) << 10) |
      ((m.tc ? 1 : 0) << 9) | ((m.rd ? 1 : 0) << 8) | ((m.ra ? 1 : 0) << 7) |
      ((m.ad ? 1 : 0) << 5) | ((m.cd ? 1 : 0) << 4) | (RCODES[m.rcode] || 0)
    );
  }

  function encode(msg, tcp) {
    const w = new Writer(tcp ? 2 : 0);
    if (tcp) w.seg('TCP length prefix (2 bytes, RFC 1035 §4.2.2)', 'len', () => w.u16(0));
    const m = msg;
    const arCount = m.ar.length + (m.edns ? 1 : 0);
    w.seg(`Header · Transaction ID ${hex4(m.id)}`, 'hdr', () => w.u16(m.id));
    w.seg(`Header · Flags ${hex4(flagsWord(m))} (${flagSummary(m)})`, 'hdr', () => w.u16(flagsWord(m)));
    w.seg(`Header · QDCOUNT ${m.qd.length}`, 'hdr', () => w.u16(m.qd.length));
    w.seg(`Header · ANCOUNT ${m.an.length}`, 'hdr', () => w.u16(m.an.length));
    w.seg(`Header · NSCOUNT ${m.ns.length}`, 'hdr', () => w.u16(m.ns.length));
    w.seg(`Header · ARCOUNT ${arCount}`, 'hdr', () => w.u16(arCount));
    for (const q of m.qd) {
      w.seg(`Question · QNAME ${q.name}`, 'q', () => w.name(q.name, true));
      w.seg(`Question · QTYPE ${q.type} (${TYPES[q.type]})`, 'q', () => w.u16(TYPES[q.type] || 0));
      w.seg('Question · QCLASS IN (1)', 'q', () => w.u16(1));
    }
    for (const rr of m.an) encRR(w, rr, 'an');
    for (const rr of m.ns) encRR(w, rr, 'ns');
    for (const rr of m.ar) encRR(w, rr, 'ar');
    if (m.edns) {
      w.seg('OPT pseudo-RR · root name', 'opt', () => w.u8(0));
      w.seg('OPT · TYPE 41', 'opt', () => w.u16(41));
      w.seg(`OPT · UDP payload size ${m.edns.udp}`, 'opt', () => w.u16(m.edns.udp));
      w.seg(`OPT · ext-RCODE 0, version 0, DO=${m.edns.do ? 1 : 0}`, 'opt', () => {
        w.u8(0); w.u8(0); w.u16(m.edns.do ? 0x8000 : 0);
      });
      const opts = [];
      if (m.edns.ede) {
        const txt = utf8(m.edns.ede.text || '');
        opts.push({ code: 15, bytes: [(m.edns.ede.code >> 8) & 255, m.edns.ede.code & 255, ...txt], label: `EDE ${m.edns.ede.code} (${m.edns.ede.text})` });
      }
      const optLen = opts.reduce((a, o) => a + 4 + o.bytes.length, 0);
      w.seg(`OPT · RDLENGTH ${optLen}`, 'opt', () => w.u16(optLen));
      for (const o of opts) w.seg(`OPT option · ${o.label}`, 'opt', () => { w.u16(o.code); w.u16(o.bytes.length); w.bytes(o.bytes); });
    }
    if (tcp) {
      const len = w.pos - 2;
      w.b[0] = len >> 8;
      w.b[1] = len & 255;
      w.segs[0].label = `TCP length prefix = ${len} bytes (RFC 1035 §4.2.2)`;
    }
    return { bytes: w.b, segs: w.segs.sort((a, b) => a.start - b.start) };
  }

  function flagSummary(m) {
    const f = [];
    f.push(m.qr ? 'response' : 'query');
    if (m.opcode && m.opcode !== 'QUERY') f.push(m.opcode);
    ['aa', 'tc', 'rd', 'ra', 'ad', 'cd'].forEach((k) => { if (m[k]) f.push(k.toUpperCase()); });
    if (m.qr) f.push(m.rcode);
    return f.join(' ');
  }

  /* ---------- records & packets ---------- */
  let seed = 0x3a7c;
  function nextId() {
    seed = (Math.imul(seed, 1103515245) + 12345) & 0x7fffffff;
    return (seed >> 8) & 0xffff;
  }
  function nextPort() {
    return 49152 + (nextId() % 16383);
  }

  const rr = (name, ttl, type, data) => ({ name: fqdn(name), ttl, type, data });

  /**
   * Build a DNS query packet.
   * o: {src, dst, v, sport, dport, id, name, type, rd, cd, ad, edns, do, tcp, note, opcode}
   */
  function query(o) {
    const edns = o.edns === false ? null : Object.assign({ udp: 1232, do: !!o.do }, o.edns || {});
    return {
      kind: 'dns',
      ip: { v: o.v || 4, src: o.src, dst: o.dst },
      l4: { proto: o.tcp ? 'TCP' : 'UDP', sport: o.sport || nextPort(), dport: o.dport || 53 },
      dns: {
        id: o.id ?? nextId(), qr: 0, opcode: o.opcode || 'QUERY', aa: 0, tc: 0,
        rd: o.rd === undefined ? 1 : o.rd ? 1 : 0, ra: 0, ad: o.ad ? 1 : 0, cd: o.cd ? 1 : 0,
        rcode: 'NOERROR', qd: [{ name: fqdn(o.name), type: o.type || 'A' }], an: [], ns: [], ar: [], edns,
      },
      note: o.note, label: o.label, via: o.via,
    };
  }

  /**
   * Build the response to a query packet (ports/addresses swapped, same ID & question).
   * o: {aa, ra, ad, tc, rcode, an, ns, ar, note, edns, tcp, qd, src}
   */
  function response(q, o) {
    o = o || {};
    const qd = q.dns.qd.map((x) => Object.assign({}, x));
    if (o.qname) qd[0].name = fqdn(o.qname);
    let edns = q.dns.edns ? Object.assign({}, q.dns.edns, { udp: 1232 }) : null;
    if (edns && o.ede) edns.ede = o.ede;
    return {
      kind: 'dns',
      ip: { v: q.ip.v, src: o.src || q.ip.dst, dst: q.ip.src },
      l4: { proto: o.tcp !== undefined ? (o.tcp ? 'TCP' : 'UDP') : q.l4.proto, sport: q.l4.dport, dport: o.dport || q.l4.sport },
      dns: {
        id: o.id ?? q.dns.id, qr: 1, opcode: q.dns.opcode, aa: o.aa ? 1 : 0, tc: o.tc ? 1 : 0,
        rd: q.dns.rd, ra: o.ra ? 1 : 0, ad: o.ad ? 1 : 0, cd: q.dns.cd,
        rcode: o.rcode || 'NOERROR', qd, an: o.an || [], ns: o.ns || [], ar: o.ar || [], edns,
      },
      note: o.note, label: o.label, forged: o.forged,
    };
  }

  /**
   * Generic (non-DNS) packet: TCP/TLS/HTTP/SMTP/QUIC/…
   * o: {src, dst, v, proto, sport, dport, summary, label, layers:[{name, fields:[[k,v]]}], note, enc, inner, size}
   */
  function generic(o) {
    return Object.assign({ kind: 'gen', ip: o.src ? { v: o.v || 4, src: o.src, dst: o.dst } : null,
      l4: o.proto ? { proto: o.proto, sport: o.sport, dport: o.dport } : null }, o);
  }

  /** Wrap a packet in an encrypted TLS/HTTPS/QUIC envelope. */
  function encrypted(inner, o) {
    return generic(Object.assign({
      src: inner.ip.src, dst: inner.ip.dst, v: inner.ip.v, enc: true, inner,
    }, o));
  }

  /* ---------- descriptions ---------- */
  function shortLabel(p) {
    if (p.label) return p.label;
    if (p.kind !== 'dns') return p.summary || p.kind;
    const m = p.dns, q = m.qd[0];
    if (!m.qr) return `${m.opcode !== 'QUERY' ? m.opcode + ' ' : ''}${q.type}? ${bare(q.name)}`;
    if (m.tc) return 'TC=1 (truncated)';
    if (m.rcode !== 'NOERROR') return m.rcode;
    if (m.an.length) {
      const a = m.an.find((r) => r.type === q.type) || m.an[0];
      const more = m.an.filter((r) => r.type !== 'RRSIG').length - 1;
      return `${a.type} ${a.type === 'TXT' ? '"…"' : bare(a.data.split(' ').length > 3 ? a.data.split(' ').slice(0, 2).join(' ') + '…' : a.data)}${more > 0 ? ` +${more}` : ''}`;
    }
    const nsr = m.ns.find((r) => r.type === 'NS');
    if (nsr) return `Referral → ${bare(nsr.name)} NS`;
    return 'NODATA';
  }

  function summary(p) {
    if (p.summary) return p.summary;
    if (p.kind !== 'dns') return p.kind;
    const m = p.dns, q = m.qd[0];
    let s = `${m.opcode === 'NOTIFY' ? 'Notify' : 'Standard query'}${m.qr ? ' response' : ''} ${hex4(m.id)} ${q.type} ${bare(q.name)}`;
    if (m.qr) {
      if (m.rcode !== 'NOERROR') s += ` ${m.rcode}`;
      m.an.slice(0, 3).forEach((r) => (s += ` ${r.type} ${bare(r.data).split(' ')[0]}`));
      if (m.an.length > 3) s += ' …';
      if (!m.an.length && m.ns.some((r) => r.type === 'NS')) s += ` NS ${bare(m.ns.find((r) => r.type === 'NS').data)} (referral)`;
    }
    if (m.edns) s += ' OPT';
    return s;
  }

  const cache = new WeakMap();
  function wire(p) {
    if (p.kind !== 'dns') return null;
    if (!cache.has(p)) cache.set(p, encode(p.dns, p.l4 && p.l4.proto === 'TCP'));
    return cache.get(p);
  }

  /** Deterministic pseudo-random bytes (for encrypted payloads). */
  function noise(seedStr, n) {
    let h = 2166136261;
    for (const c of seedStr) h = Math.imul(h ^ c.charCodeAt(0), 16777619);
    const out = [];
    for (let i = 0; i < n; i++) {
      h ^= h << 13; h ^= h >>> 17; h ^= h << 5;
      out.push(h & 255);
    }
    return out;
  }

  /** Illustrative key / signature material (random-looking, valid base64). */
  function fakeB64(seedStr, n) {
    return btoa(String.fromCharCode.apply(null, noise(seedStr, n)));
  }
  function fakeHex(seedStr, n) {
    return noise(seedStr, n).map(hex2).join('').toUpperCase();
  }

  function hashStr(s) {
    let h = 2166136261;
    for (const c of s) h = Math.imul(h ^ c.charCodeAt(0), 16777619);
    return h >>> 0;
  }

  DV.dns = {
    TYPES, RCODES, rr, query, response, generic, encrypted, encode, wire, summary, shortLabel,
    flagSummary, flagsWord, hex4, hex2, fqdn, bare, noise, hashStr, fakeB64, fakeHex, nextId, nextPort,
    seed(n) { seed = n; },
    ipv4Bytes, ipv6Bytes, ipv6Expand, ipv6Compress, reverse4, reverse6, embed64,
  };

  /* ---------- the shared "world" of addresses used across lessons ----------
   * Addresses use the documentation ranges (RFC 5737 / RFC 3849) except for
   * the real, well-known root and .com server addresses.                     */
  DV.world = {
    client: { name: 'laptop', ip4: '192.0.2.10', ip6: '2001:db8:c1::10' },
    client2: { name: 'phone', ip4: '192.0.2.23', ip6: '2001:db8:c1::23' },
    resolver: { name: 'resolver.isp.example', ip4: '198.51.100.53', ip6: '2001:db8:53::53' },
    root: { name: 'a.root-servers.net', ip4: '198.41.0.4', ip6: '2001:503:ba3e::2:30' },
    com: { name: 'a.gtld-servers.net', ip4: '192.5.6.30', ip6: '2001:503:a83e::2:30' },
    auth: { name: 'ns1.example.com', ip4: '203.0.113.53', ip6: '2001:db8:113::53' },
    web: { name: 'www.example.com', ip4: '203.0.113.10', ip6: '2001:db8:113::10' },
    cdn: { name: 'edge.cdn.example', ip4: '203.0.113.200', ip6: '2001:db8:113::200' },
    attacker: { name: 'attacker', ip4: '198.51.100.66', ip6: '2001:db8:66::66' },
  };

  /* Illustrative DNSSEC material. The root KSK tag 20326 is the real KSK-2017;
     the other tags, keys and digests are made up for teaching. */
  DV.world.keys = {
    root: { ksk: { tag: 20326, alg: 8, key: fakeB64('root-ksk', 260) }, zsk: { tag: 53148, alg: 8, key: fakeB64('root-zsk', 260) } },
    com: { ksk: { tag: 19718, alg: 13, key: fakeB64('com-ksk', 64) }, zsk: { tag: 4534, alg: 13, key: fakeB64('com-zsk', 64) }, ds: fakeHex('com-ds', 32) },
    ex: { ksk: { tag: 31589, alg: 13, key: fakeB64('ex-ksk', 64) }, zsk: { tag: 48213, alg: 13, key: fakeB64('ex-zsk', 64) }, ds: fakeHex('ex-ds', 32) },
  };
  /** RRSIG RDATA string. */
  DV.dns.rrsig = function (covered, alg, labels, ttl, tag, signer, seedStr) {
    const n = alg === 8 ? 256 : 64;
    return `${covered} ${alg} ${labels} ${ttl} 20261024000000 20260924000000 ${tag} ${fqdn(signer)} ${fakeB64(seedStr || covered + signer + tag, n)}`;
  };
  DV.dns.dnskey = (k, ksk) => `${ksk ? 257 : 256} 3 ${k.alg} ${k.key}`;
})();
