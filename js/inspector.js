/* inspector.js — Wireshark-style packet inspector with a live hex dump. */
(function () {
  'use strict';
  const DV = (window.DV = window.DV || {});
  const esc = (s) => DV.esc(s);
  const D = () => DV.dns;

  const FLAG_INFO = {
    QR: ['Query (0) / Response (1)', 1],
    Opcode: ['0 = standard QUERY, 4 = NOTIFY, 5 = UPDATE', 4],
    AA: ['Authoritative Answer: the responding server is authoritative for the zone', 1],
    TC: ['TrunCation: the response did not fit, so retry over TCP', 1],
    RD: ['Recursion Desired: "please resolve this fully for me"', 1],
    RA: ['Recursion Available: the server offers recursion', 1],
    Z: ['Reserved, must be zero', 1],
    AD: ['Authentic Data: the resolver validated this answer with DNSSEC', 1],
    CD: ['Checking Disabled: the client asks the resolver not to validate', 1],
    RCODE: ['Response code: 0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN, 5 REFUSED', 4],
  };
  const TYPE_HELP = {
    A: 'IPv4 address (32 bits)', AAAA: 'IPv6 address (128 bits)', NS: 'Name server for the zone',
    CNAME: 'Canonical name (alias)', SOA: 'Start of authority', PTR: 'Pointer (reverse DNS)', MX: 'Mail exchanger',
    TXT: 'Text strings', SRV: 'Service locator', DS: 'Delegation signer (hash of child KSK)',
    RRSIG: 'Signature over an RRset', NSEC: 'Next secure name (authenticated denial)',
    NSEC3: 'Hashed next secure name', DNSKEY: 'Zone public key', HTTPS: 'HTTPS service binding',
    SVCB: 'Service binding', CAA: 'Certification authority authorization',
  };

  function row(k, v, cls) {
    return `<div class="kv ${cls || ''}"><span class="k">${k}</span><span class="v">${v}</span></div>`;
  }
  function section(title, body, open = true, cls = '') {
    return `<details class="tree-sec ${cls}" ${open ? 'open' : ''}><summary>${title}</summary><div class="tree-body">${body}</div></details>`;
  }

  function ipLayer(p, payloadLen) {
    if (!p.ip) return '';
    const v6 = p.ip.v === 6;
    const proto = p.l4 ? p.l4.proto : 'UDP';
    const pnum = { TCP: 6, UDP: 17, QUIC: 17 }[proto] || 17;
    const hdr = v6 ? 40 : 20;
    const total = payloadLen ? payloadLen + hdr : null;
    const body = v6
      ? row('Version', '6') + row('Traffic class / Flow label', '0x00 / 0x' + (D().hashStr(p.ip.src + p.ip.dst) & 0xfffff).toString(16)) +
        (total ? row('Payload length', total - 40) : '') + row('Next header', `${pnum} (${proto === 'TCP' ? 'TCP' : 'UDP'})`) +
        row('Hop limit', 64) + row('Source', `<span class="mono">${esc(p.ip.src)}</span>`) + row('Destination', `<span class="mono">${esc(p.ip.dst)}</span>`)
      : row('Version / IHL', '4 / 20 bytes') + (total ? row('Total length', total) : '') + row('TTL', 64) +
        row('Protocol', `${pnum} (${proto === 'TCP' ? 'TCP' : 'UDP'})`) +
        row('Source', `<span class="mono">${esc(p.ip.src)}</span>`) + row('Destination', `<span class="mono">${esc(p.ip.dst)}</span>`);
    return section(`Internet Protocol Version ${v6 ? 6 : 4}, Src: ${esc(p.ip.src)}, Dst: ${esc(p.ip.dst)}`, body, false, 'l-ip');
  }

  function l4Layer(p, payloadLen) {
    if (!p.l4) return '';
    const { proto, sport, dport } = p.l4;
    let body = row('Source port', sport) + row('Destination port', dport + portName(dport));
    if (proto === 'UDP' && payloadLen) body += row('Length', payloadLen + 8);
    if (proto === 'TCP' && p.tcpFlags) body += row('Flags', p.tcpFlags);
    const name = proto === 'TCP' ? 'Transmission Control Protocol' : proto === 'QUIC' ? 'User Datagram Protocol (QUIC)' : 'User Datagram Protocol';
    return section(`${name}, Src Port: ${sport}, Dst Port: ${dport}`, body, false, 'l-l4');
  }
  function portName(p) {
    const m = { 53: 'domain', 853: 'domain-s (DoT)', 443: 'https', 80: 'http', 25: 'smtp', 587: 'submission', 5061: 'sips', 5060: 'sip', 993: 'imaps' };
    return m[p] ? ` <em>(${m[p]})</em>` : '';
  }

  function flagBits(m) {
    const op = { QUERY: 0, NOTIFY: 4, UPDATE: 5 }[m.opcode] || 0;
    const rc = D().RCODES[m.rcode] || 0;
    const fields = [
      ['QR', m.qr], ['Opcode', op.toString(2).padStart(4, '0')], ['AA', m.aa], ['TC', m.tc], ['RD', m.rd], ['RA', m.ra],
      ['Z', 0], ['AD', m.ad], ['CD', m.cd], ['RCODE', rc.toString(2).padStart(4, '0')],
    ];
    return `<div class="bits">${fields
      .map(([k, v]) => {
        const [help, w] = FLAG_INFO[k];
        const on = String(v).includes('1');
        return `<div class="bit ${on ? 'on' : ''}" style="flex:${w}" title="${esc(k + ': ' + help)}"><span class="bk">${k}</span><span class="bv mono">${v}</span></div>`;
      })
      .join('')}</div>`;
  }

  function rrTable(list) {
    return `<table class="rrt"><thead><tr><th>Name</th><th>TTL</th><th>Type</th><th>Data</th></tr></thead><tbody>${list
      .map((r) => `<tr><td class="mono">${esc(r.name)}</td><td class="mono">${r.ttl}</td><td><span class="rtype" title="${esc(TYPE_HELP[r.type] || '')}">${r.type}</span></td><td class="mono wrap">${esc(r.data)}</td></tr>`)
      .join('')}</tbody></table>`;
  }

  function dnsLayer(p) {
    const m = p.dns;
    const flagsHex = D().hex4(D().flagsWord(m));
    let body = row('Transaction ID', `<span class="mono">${D().hex4(m.id)}</span>`) +
      row('Flags', `<span class="mono">${flagsHex}</span> — ${esc(D().flagSummary(m))}`) + flagBits(m) +
      row('Counts', `Questions ${m.qd.length} · Answer ${m.an.length} · Authority ${m.ns.length} · Additional ${m.ar.length + (m.edns ? 1 : 0)}`);
    body += section('Question', `<table class="rrt"><thead><tr><th>Name</th><th>Type</th><th>Class</th></tr></thead><tbody>${m.qd
      .map((q) => `<tr><td class="mono">${esc(q.name)}</td><td><span class="rtype">${q.type}</span></td><td>IN</td></tr>`)
      .join('')}</tbody></table>`, true, 'g-q');
    if (m.an.length) body += section(`Answer section (${m.an.length})`, rrTable(m.an), true, 'g-an');
    if (m.ns.length) body += section(`Authority section (${m.ns.length})`, rrTable(m.ns), true, 'g-ns');
    if (m.ar.length) body += section(`Additional section (${m.ar.length})`, rrTable(m.ar), true, 'g-ar');
    if (m.edns) {
      body += section('EDNS(0) OPT pseudo-record', row('UDP payload size', m.edns.udp + ' bytes') +
        row('DO bit (DNSSEC OK)', m.edns.do ? '1 — send me DNSSEC records' : '0') + row('Version', 0) +
        (m.edns.ede ? row('Extended DNS Error', `${m.edns.ede.code} — ${esc(m.edns.ede.text)}`, 'bad') : ''), false, 'g-opt');
    }
    const title = `Domain Name System (${m.qr ? 'response' : 'query'})`;
    return section(title, body, true, 'l-dns');
  }

  function genLayers(p) {
    return (p.layers || [])
      .map((L) => section(esc(L.name), L.fields.map(([k, v]) => row(esc(k), v)).join('') + (L.html || ''), L.open !== false, L.cls || ''))
      .join('');
  }

  function hexDump(bytes, segs, cap) {
    const segOf = new Array(bytes.length).fill(-1);
    segs.forEach((s, i) => { for (let k = s.start; k < s.end; k++) segOf[k] = i; });
    let rows = '';
    for (let off = 0; off < bytes.length; off += 8) {
      let hx = '', asc = '';
      for (let k = off; k < off + 8; k++) {
        if (k < bytes.length) {
          const s = segOf[k];
          const g = s >= 0 ? segs[s].group : '';
          hx += `<span class="hb g-${g}" data-s="${s}">${D().hex2(bytes[k])}</span>`;
          const c = bytes[k];
          asc += `<span class="hb g-${g}" data-s="${s}">${c >= 32 && c < 127 ? esc(String.fromCharCode(c)) : '·'}</span>`;
        } else hx += '<span class="hb pad">  </span>';
      }
      rows += `<div class="hrow"><span class="hoff">${off.toString(16).padStart(4, '0')}</span><span class="hhex">${hx}</span><span class="hasc">${asc}</span></div>`;
    }
    return `<div class="hexdump mono">${rows}</div><div class="hex-cap">${cap || 'Hover over the bytes to see which field each one encodes.'}</div>`;
  }

  function wireSection(p) {
    const w = D().wire(p);
    if (!w) return '';
    const n = w.bytes.length;
    const legend = [['len', 'TCP length'], ['hdr', 'Header'], ['q', 'Question'], ['an', 'Answer'], ['ns', 'Authority'], ['ar', 'Additional'], ['opt', 'EDNS OPT']]
      .filter(([g]) => w.segs.some((s) => s.group === g))
      .map(([g, t]) => `<span class="lg g-${g}">${t}</span>`)
      .join('');
    const note = `DNS message: <b>${n - (p.l4.proto === 'TCP' ? 2 : 0)} bytes</b>. Names are compressed with pointers (<span class="mono">c0 xx</span>) exactly as real servers do.`;
    return `<details class="tree-sec hex-sec" open><summary>Wire format — ${n} bytes</summary><div class="tree-body"><div class="hex-legend">${legend}</div>${hexDump(w.bytes, w.segs)}<div class="hex-note">${note}</div></div></details>`;
  }

  function payloadLen(p) {
    const w = D().wire(p);
    if (w) return w.bytes.length;
    return p.size || null;
  }

  function renderPacket(p, depth) {
    let html = '';
    const plen = payloadLen(p);
    html += ipLayer(p, plen);
    html += l4Layer(p, plen);
    if (p.kind === 'dns') html += dnsLayer(p);
    html += genLayers(p);
    if (p.enc) {
      const noise = D().noise(D().summary(p.inner || p), 64);
      const hx = noise.map((b) => D().hex2(b)).join(' ');
      html += section(`${esc(p.encName || 'TLS')} Application Data (encrypted)`,
        `<div class="cipher mono">${hx} …</div>
         <p class="muted small">An on-path observer sees only these random-looking bytes, plus the IP addresses, ports, sizes and timing.</p>
         ${p.inner ? `<button class="btn small reveal">🔓 Show the decrypted contents (only the two endpoints can see this)</button><div class="inner" hidden>${renderPacket(p.inner, (depth || 0) + 1)}</div>` : ''}`,
        true, 'l-enc');
    }
    if (p.kind === 'dns' && !depth) html += wireSection(p);
    return html;
  }

  function transportLine(p) {
    if (!p.ip) return p.local ? 'Local call on the same host (no network packet)' : '';
    const v = p.ip.v === 6 ? 'IPv6' : 'IPv4';
    const pr = p.l4 ? p.l4.proto : '';
    const b = (a, port) => (p.ip.v === 6 ? `[${a}]` : a) + (port ? ':' + port : '');
    const plen = payloadLen(p);
    const total = plen ? plen + (p.ip.v === 6 ? 40 : 20) + (pr === 'TCP' ? 20 : 8) : null;
    return `${v} · ${pr}${p.enc ? ' · encrypted' : ''} · ${esc(b(p.ip.src, p.l4 && p.l4.sport))} → ${esc(b(p.ip.dst, p.l4 && p.l4.dport))}${total ? ` · ~${total} bytes on the wire` : ''}`;
  }

  DV.inspector = {
    render(el, p, entry) {
      el.innerHTML = `
        <div class="insp-head tone-${entry ? entry.tone : 'q'}">
          <span class="pl-dot"></span>
          <div><div class="insp-num">Packet #${entry ? entry.n : ''} · step ${entry ? entry.step + 1 : ''}</div>
          <div class="insp-sum">${esc(D().summary(p))}</div></div>
        </div>
        <div class="insp-meta mono">${transportLine(p)}</div>
        ${p.note ? `<div class="insp-note">${p.note}</div>` : ''}
        ${p.forged ? '<div class="insp-note bad">⚠ Forged packet: the source IP address is spoofed.</div>' : ''}
        <div class="tree">${renderPacket(p)}</div>`;
      const cap = el.querySelector('.hex-cap');
      const dump = el.querySelector('.hexdump');
      if (dump) {
        const w = D().wire(p);
        dump.addEventListener('mouseover', (e) => {
          const s = e.target.dataset && e.target.dataset.s;
          if (s === undefined) return;
          dump.querySelectorAll('.hb.on').forEach((x) => x.classList.remove('on'));
          if (+s < 0) return;
          dump.querySelectorAll(`.hb[data-s="${s}"]`).forEach((x) => x.classList.add('on'));
          const seg = w.segs[+s];
          cap.innerHTML = `<b>${esc(seg.label)}</b> <span class="muted">(bytes ${seg.start}–${seg.end - 1})</span>`;
        });
        dump.addEventListener('mouseleave', () => dump.querySelectorAll('.hb.on').forEach((x) => x.classList.remove('on')));
      }
      el.querySelectorAll('.reveal').forEach((b) => {
        b.onclick = () => {
          const inner = b.nextElementSibling;
          inner.hidden = !inner.hidden;
          b.textContent = inner.hidden ? '🔓 Show the decrypted contents (only the two endpoints can see this)' : '🔒 Hide the decrypted contents';
        };
      });
    },
  };
})();
