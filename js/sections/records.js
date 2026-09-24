/* Section 4 — Record types: an animated lookup + zone-file view for each common RR type. */
(function () {
  'use strict';
  const DV = window.DV;
  const D = DV.dns, Wd = DV.world;
  const rr = D.rr;
  const C = Wd.client, R = Wd.resolver, A = Wd.auth;
  const K = Wd.keys.ex;
  const SOA = 'ns1.example.com. hostmaster.example.com. 2026092401 7200 3600 1209600 300';
  const short = (s, n) => (s.length > n ? s.slice(0, n) + '…' : s);

  /* ---- the example.com zone file shown in the side panel ---- */
  const ZONE = [
    ['c', '; example.com zone file (primary: ns1.example.com)'],
    ['', '$ORIGIN example.com.'],
    ['', '$TTL 3600'],
    ['soa', '@          IN SOA    ns1.example.com. hostmaster.example.com. ('],
    ['soa', '                     2026092401 ; serial'],
    ['soa', '                     7200       ; refresh'],
    ['soa', '                     3600       ; retry'],
    ['soa', '                     1209600    ; expire'],
    ['soa', '                     300 )      ; minimum / negative TTL'],
    ['ns', '@          IN NS     ns1.example.com.'],
    ['ns', '@          IN NS     ns2.example.net.'],
    ['ns1a', 'ns1        IN A      203.0.113.53'],
    ['ns1aaaa', 'ns1        IN AAAA   2001:db8:113::53'],
    ['apexa', '@          IN A      203.0.113.10'],
    ['wwwa', 'www        IN A      203.0.113.10'],
    ['wwwaaaa', 'www        IN AAAA   2001:db8:113::10'],
    ['shop', 'shop       IN CNAME  shops.saas.example.'],
    ['mx', '@          IN MX     10 mx1.example.com.'],
    ['mx', '@          IN MX     20 mx2.example.com.'],
    ['mxa', 'mx1        IN A      203.0.113.25'],
    ['mxa', 'mx2        IN A      203.0.113.26'],
    ['txt', '@          IN TXT    "v=spf1 mx -all"'],
    ['txt', '@          IN TXT    "site-verification=a1b2c3d4e5"'],
    ['srv', '_sips._tcp IN SRV    10 60 5061 sip1.example.com.'],
    ['caa', '@          IN CAA    0 issue "letsencrypt.org"'],
    ['caa', '@          IN CAA    0 iodef "mailto:security@example.com"'],
    ['https', 'www        IN HTTPS  1 . alpn=h3,h2 ipv4hint=203.0.113.10'],
    ['c', '; ---- added by the DNSSEC signer ----'],
    ['dnskey', `@          IN DNSKEY 257 3 13 ${short(K.ksk.key, 14)} ; KSK ${K.ksk.tag}`],
    ['dnskey', `@          IN DNSKEY 256 3 13 ${short(K.zsk.key, 14)} ; ZSK ${K.zsk.tag}`],
    ['rrsig', `www        IN RRSIG  A 13 3 3600 20261024… ${K.zsk.tag} example.com. …`],
    ['nsec', 'mx2        IN NSEC   ns1.example.com. A RRSIG NSEC'],
    ['c', '; ---- in the parent zone (com.) ----'],
    ['del', 'example.com. IN NS   ns1.example.com.'],
    ['ds', `example.com. IN DS   ${K.ksk.tag} 13 2 ${short(K.ds, 12)}`],
    ['c', '; ---- reverse zone 113.0.203.in-addr.arpa. ----'],
    ['ptr', '10         IN PTR    www.example.com.'],
    ['ptr25', '25         IN PTR    mx1.example.com.'],
  ];
  const zoneHtml = `<div class="zone">${ZONE.map(([k, t]) => `<div class="zl ${k === 'c' ? 'c' : ''}" data-k="${k}">${DV.esc(t)}</div>`).join('')}</div>`;

  /* ---- a standard lookup: client → resolver → auth and back ---- */
  function lookup(name, type, an, o) {
    o = o || {};
    const src = o.src || C.ip4;
    const srv = o.server || 'auth';
    const srvIp = o.serverIp || A.ip4;
    const q = D.query({ src, dst: R.ip4, name, type, do: o.do });
    const qa = D.query({ src: R.ip4, dst: srvIp, name, type, rd: 0, do: o.do });
    const ra = D.response(qa, { aa: 1, an, ns: o.ns, ar: o.ar, rcode: o.rcode, note: o.anote });
    const r = D.response(q, { ra: 1, ad: o.ad, an: o.clientAn || an, ns: o.clientNs || o.ns, rcode: o.rcode, note: o.note });
    const who = o.client || 'client';
    return {
      ask: { send: [who, 'resolver'], pkt: q },
      fwd: { send: ['resolver', srv], pkt: qa },
      back: { send: [srv, 'resolver'], pkt: ra },
      ret: { send: ['resolver', who], pkt: r },
      q, qa, ra, r,
    };
  }
  const chips = (arr, cls) => `<div class="chips">${arr.map((x, i) => `<span class="chip ${cls ? cls(i) : ''}" style="animation-delay:${i * 60}ms">${x}</span>`).join('')}</div>`;
  const bytes = (arr, cls) => `<div class="bytes ${cls}">${arr.map((b, i) => `<span style="animation-delay:${i * 40}ms">${D.hex2(b)}</span>`).join('')}</div>`;

  /* ---- per-type lessons ---- */
  const T = {};

  T.A = () => {
    const L = lookup('www.example.com', 'A', [rr('www.example.com', 3600, 'A', Wd.web.ip4)]);
    return [
      { title: 'A: name → IPv4 address', focus: ['auth'], text: '<p>The <b>A</b> record (type 1) maps a hostname to a <b>32-bit IPv4 address</b>, so its RDATA is always exactly 4 bytes. It is the most frequently queried record type on the Internet.</p>',
        actions: [{ hl: ['wwwa', 'apexa'] }, { overlay: { id: 'f', at: 'bl', title: 'Anatomy', html: '<pre>www  3600  IN  A  203.0.113.10\nname  TTL  class type  RDATA</pre>RDATA on the wire (4 bytes):' + bytes(D.ipv4Bytes(Wd.web.ip4), 'v4') } }] },
      { title: 'Query www.example.com A', focus: ['client', 'resolver', 'auth'], text: '<p>The client asks its resolver, which asks the authoritative server (the referrals are already cached).</p>', actions: [L.ask, L.fwd] },
      { title: 'Answer', focus: ['auth', 'resolver', 'client'], text: '<p>One A record comes back. A name can have <b>several</b> A records: the resolver returns them all, often rotating the order (round-robin), and the client picks one, typically the first.</p>', deep: '<p>The zone apex (<code>example.com</code> itself) can have A records, unlike CNAMEs. Hosting several A records is the simplest form of DNS load distribution, but DNS has no health checks: a dead IP keeps being handed out until someone removes it.</p>',
        actions: [L.back, L.ret, { badge: 'client', text: '203.0.113.10', tone: 'ok' }] },
    ];
  };

  T.AAAA = () => {
    const L = lookup('www.example.com', 'AAAA', [rr('www.example.com', 3600, 'AAAA', Wd.web.ip6)]);
    return [
      { title: 'AAAA: name → IPv6 address', focus: ['auth'], text: '<p>The <b>AAAA</b> ("quad-A", type 28) record holds a <b>128-bit IPv6 address</b>, so its RDATA is 16 bytes (four times the size of an A record, hence the name).</p>',
        actions: [{ hl: ['wwwaaaa', 'ns1aaaa'] }, { overlay: { id: 'f', at: 'bl', title: '2001:db8:113::10 on the wire (16 bytes)', html: bytes(D.ipv6Bytes(Wd.web.ip6), 'v6') + '<div class="small muted">The "::" shorthand expands to the run of zero bytes.</div>' } }] },
      { title: 'Query www.example.com AAAA', focus: ['client', 'resolver', 'auth'], text: '<p>Dual-stack clients usually send the A and AAAA queries at the same time. The <i>transport</i> (IPv4 here) doesn\'t depend on the record type being asked for.</p>', actions: [L.ask, L.fwd] },
      { title: 'Answer', focus: ['auth', 'resolver', 'client'], text: '<p>The client will usually prefer the IPv6 address (RFC 6724) and race it against IPv4 with Happy Eyeballs. The <a href="#ipv6">IPv4 vs IPv6</a> lesson goes deeper.</p>', actions: [L.back, L.ret, { badge: 'client', text: '2001:db8:113::10', tone: 'ok' }] },
    ];
  };

  T.CNAME = () => {
    const cn = rr('shop.example.com', 3600, 'CNAME', 'shops.saas.example.');
    const aT = rr('shops.saas.example', 300, 'A', '198.51.100.80');
    const L = lookup('shop.example.com', 'A', [cn], { clientAn: [cn, aT] });
    const q2 = D.query({ src: R.ip4, dst: '198.51.100.8', name: 'shops.saas.example', type: 'A', rd: 0, note: 'The resolver restarts the lookup with the CNAME target as the new QNAME.' });
    const r2 = D.response(q2, { aa: 1, an: [aT] });
    return [
      { title: 'CNAME: an alias for another name', focus: ['auth'], text: '<p>A <b>CNAME</b> (canonical name) says "this name is an alias; look up <i>that</i> name instead". Here <code>shop.example.com</code> points to a SaaS provider\'s hostname, and the provider can change its IPs without the customer touching their zone.</p>',
        actions: [{ hl: ['shop'] }, { overlay: { id: 'r', at: 'bl', cls: 'warn', title: 'Rules', html: 'A name with a CNAME can have <b>no other records</b> (RFC 1034 §3.6.2), so there can be no CNAME at the zone apex, where SOA and NS must live.' } }] },
      { title: 'Query shop.example.com A', focus: ['client', 'resolver', 'auth'], text: '<p>The client asks for an A record, as usual. It doesn\'t know that the name is an alias.</p>', actions: [L.ask, L.fwd] },
      { title: 'Authoritative returns only the CNAME', focus: ['auth', 'resolver'], text: '<p>example.com\'s server isn\'t authoritative for <code>saas.example</code>, so it returns just the CNAME. The resolver now has to <b>restart the lookup</b> using the target name.</p>', actions: [L.back, { badge: 'resolver', text: 'follow CNAME → shops.saas.example', tone: 'warn' }] },
      { title: 'Chase the target name', focus: ['resolver', 'other'], text: '<p>The resolver resolves <code>shops.saas.example</code> from the provider\'s name servers. (If that zone\'s delegation wasn\'t cached, this could mean another full walk from the root.)</p>', deep: '<p>Every CNAME hop adds latency and a possible failure point. Resolvers cap chain length (often 8–16 hops) to stop loops. <b>DNAME</b> (RFC 6672) aliases an entire subtree instead of a single name.</p>',
        actions: [{ show: ['other'] }, { send: ['resolver', 'other'], pkt: q2 }, { send: ['other', 'resolver'], pkt: r2 }] },
      { title: 'Client receives the whole chain', focus: ['resolver', 'client'], text: '<p>The answer section contains the CNAME <b>and</b> the final A record, in order. The client connects to <code>198.51.100.80</code> but still uses <code>shop.example.com</code> in TLS SNI and HTTP Host.</p>', deep: '<p>For the apex, providers offer "CNAME flattening", ALIAS or ANAME (the provider resolves the target and serves A/AAAA records). The standards-based alternative is an HTTPS record in AliasMode.</p>',
        actions: [L.ret, { overlay: { id: 'ch', at: 'bl', title: 'Answer chain', html: chips(['shop.example.com', '→ CNAME', 'shops.saas.example', '→ A', '198.51.100.80'], (i) => (i === 4 ? 'ok' : i % 2 ? 'dim' : '')) } }] },
    ];
  };

  T.MX = () => {
    const L = lookup('example.com', 'MX', [rr('example.com', 3600, 'MX', '10 mx1.example.com.'), rr('example.com', 3600, 'MX', '20 mx2.example.com.')],
      { ar: [rr('mx1.example.com', 3600, 'A', '203.0.113.25'), rr('mx2.example.com', 3600, 'A', '203.0.113.26')], client: 'client', anote: 'In-zone addresses of the MX targets are included in the Additional section.' });
    return [
      { title: 'MX: where to deliver mail for a domain', focus: ['auth'], text: '<p><b>MX</b> records list the mail servers for a domain, each with a <b>preference</b> (lower = tried first). The target must be a hostname with A/AAAA records. It must not be a CNAME, and it can\'t be an IP literal.</p>',
        actions: [{ hl: ['mx', 'mxa'] }, { overlay: { id: 'f', at: 'bl', title: 'Anatomy', html: '<pre>@  IN MX  10  mx1.example.com.\n          pref  exchange</pre>' } }] },
      { title: 'A sending server asks example.com MX', focus: ['client', 'resolver', 'auth'], text: '<p>Any mail server with a message for <code>@example.com</code> sends this query.</p>', actions: [L.ask, L.fwd] },
      { title: 'Two MX records plus addresses', focus: ['auth', 'resolver', 'client'], text: '<p>The authoritative server adds the A records of the MX hosts to the <b>Additional</b> section, which saves the sender a round trip. The sender tries <code>mx1</code> first and <code>mx2</code> only if mx1 fails.</p><p>See the whole delivery, including SPF, DKIM and DMARC checks, in <a href="#connect">Using the answer → Email</a>.</p>',
        actions: [L.back, L.ret, { overlay: { id: 'p', at: 'bl', title: 'Delivery order', html: chips(['10 mx1 ✓ first', '20 mx2 backup'], (i) => (i ? 'dim' : 'ok')) } }] },
    ];
  };

  T.NS = () => {
    const L = lookup('example.com', 'NS', [rr('example.com', 172800, 'NS', 'ns1.example.com.'), rr('example.com', 172800, 'NS', 'ns2.example.net.')],
      { ar: [rr('ns1.example.com', 172800, 'A', A.ip4), rr('ns1.example.com', 172800, 'AAAA', A.ip6)] });
    return [
      { title: 'NS: who is authoritative for a zone', focus: ['auth'], text: '<p><b>NS</b> records name the authoritative servers for a zone. They appear in <b>two places</b>: in the parent zone (<code>com.</code>) as the <i>delegation</i>, and at the apex of the child zone itself as the authoritative copy.</p>',
        actions: [{ hl: ['ns', 'del', 'ns1a', 'ns1aaaa'] }] },
      { title: 'Query example.com NS', focus: ['client', 'resolver', 'auth'], text: '<p>Asking the zone itself returns the authoritative (child-side) NS set.</p>', actions: [L.ask, L.fwd] },
      { title: 'Two servers, two different operators', focus: ['auth', 'resolver', 'client'], text: '<p><code>ns2.example.net</code> is <b>out of bailiwick</b> (in a different zone), so no glue is needed for it. <code>ns1.example.com</code> is in bailiwick, so the parent must hold glue for it. Using name servers on different networks and providers avoids a single point of failure.</p>',
        deep: '<p>If the parent\'s delegation lists a server that doesn\'t answer authoritatively for the zone, that is a <b>lame delegation</b>. Resolvers usually prefer the child\'s NS set once they have seen it (RFC 2181 trust ranking).</p>',
        actions: [L.back, L.ret] },
    ];
  };

  T.SOA = () => {
    const L = lookup('example.com', 'SOA', [rr('example.com', 3600, 'SOA', SOA)]);
    const notify = D.query({ src: A.ip4, dst: '198.51.100.9', name: 'example.com', type: 'SOA', rd: 0, opcode: 'NOTIFY', edns: false, note: 'DNS NOTIFY (RFC 1996): the primary tells secondaries the zone has changed.' });
    const notifyAck = D.response(notify, { aa: 1 });
    const qs = D.query({ src: '198.51.100.9', dst: A.ip4, name: 'example.com', type: 'SOA', rd: 0, edns: false });
    const rs = D.response(qs, { aa: 1, an: [rr('example.com', 3600, 'SOA', SOA)], note: 'Serial 2026092401 > 2026092400 (the secondary\'s copy), so a transfer is needed.' });
    const qx = D.query({ src: '198.51.100.9', dst: A.ip4, name: 'example.com', type: 'AXFR', rd: 0, tcp: true, edns: false, note: 'Zone transfers run over TCP. In production they are authenticated with TSIG (RFC 8945) or encrypted with XFR-over-TLS (RFC 9103).' });
    const rx = D.response(qx, { aa: 1, an: [rr('example.com', 3600, 'SOA', SOA), rr('example.com', 172800, 'NS', 'ns1.example.com.'), rr('www.example.com', 3600, 'A', Wd.web.ip4), rr('example.com', 3600, 'MX', '10 mx1.example.com.'), rr('example.com', 3600, 'SOA', SOA)], note: 'AXFR: the whole zone, framed by the SOA record at the start and the end (trimmed here).' });
    return [
      { title: 'SOA: the zone\'s administrative record', focus: ['auth'], text: '<p>Every zone has exactly one <b>SOA</b> (Start of Authority) record at its apex. It names the primary server and the admin mailbox, and carries the timers secondaries use to stay in sync.</p>',
        actions: [{ hl: ['soa'] }, { overlay: { id: 'f', at: 'bl', w: 380, title: 'SOA fields', html: '<table><tr><th>MNAME</th><td>ns1.example.com (primary)</td></tr><tr><th>RNAME</th><td>hostmaster.example.com = hostmaster@example.com</td></tr><tr><th>SERIAL</th><td>2026092401 (YYYYMMDDnn by convention)</td></tr><tr><th>REFRESH</th><td>7200 s: how often secondaries poll</td></tr><tr><th>RETRY</th><td>3600 s: retry after a failed poll</td></tr><tr><th>EXPIRE</th><td>1209600 s: stop serving if the primary is unreachable</td></tr><tr><th>MINIMUM</th><td>300 s: negative-caching TTL</td></tr></table>' } }] },
      { title: 'Query example.com SOA', focus: ['client', 'resolver', 'auth'], text: '<p>SOA records also appear unrequested in the authority section of every NXDOMAIN or NODATA response, where they set the negative-caching TTL.</p>', actions: [L.ask, L.fwd, L.back, L.ret] },
      { title: 'Zone changed: NOTIFY the secondary', focus: ['auth', 'other'], text: '<p>The admin edits the zone and increments the <b>serial</b>. The primary sends a <b>NOTIFY</b> to its secondary servers (opcode 4) instead of waiting for their REFRESH timer.</p>',
        actions: [{ show: ['other'] }, { send: ['auth', 'other'], pkt: notify, tone: 'warn' }, { send: ['other', 'auth'], pkt: notifyAck }] },
      { title: 'Secondary compares serials', focus: ['other', 'auth'], text: '<p>The secondary asks for the SOA record and compares serial numbers. The new serial is higher, so its copy is out of date.</p>', deep: '<p>Serials use sequence-space arithmetic (RFC 1982), so they can wrap around. This is also why "decrementing" a serial doesn\'t work: secondaries will ignore the change.</p>',
        actions: [{ send: ['other', 'auth'], pkt: qs }, { send: ['auth', 'other'], pkt: rs }, { badge: 'other', text: '2026092401 > 2026092400', tone: 'warn' }] },
      { title: 'Zone transfer (AXFR over TCP)', focus: ['other', 'auth'], text: '<p>The secondary pulls the zone over TCP. <b>AXFR</b> transfers the whole zone. <b>IXFR</b> (RFC 1995) transfers only the changes since a given serial.</p>',
        actions: [{ link: ['auth', 'other'], id: 'x', tone: 'gen', label: 'TCP :53 zone transfer' }, { send: ['other', 'auth'], pkt: qx }, { send: ['auth', 'other'], pkt: rx, big: true }, { badge: 'other', text: 'in sync ✓', tone: 'ok' }] },
    ];
  };

  T.TXT = () => {
    const L = lookup('example.com', 'TXT', [rr('example.com', 3600, 'TXT', '"v=spf1 mx -all"'), rr('example.com', 3600, 'TXT', '"site-verification=a1b2c3d4e5"')]);
    return [
      { title: 'TXT: free-form text, heavily used for policy', focus: ['auth'], text: '<p><b>TXT</b> records hold one or more strings of up to 255 bytes each. Because almost anyone can publish them, they became the standard place for domain <b>policies and proofs of control</b>.</p>',
        actions: [{ hl: ['txt'] }, { overlay: { id: 'u', at: 'bl', w: 400, title: 'Common TXT uses', html: '<table><tr><td><code>@</code></td><td>SPF: <code>v=spf1 …</code></td></tr><tr><td><code>sel._domainkey</code></td><td>DKIM public key</td></tr><tr><td><code>_dmarc</code></td><td>DMARC policy</td></tr><tr><td><code>_acme-challenge</code></td><td>ACME dns-01 (TLS certificates)</td></tr><tr><td><code>_mta-sts</code></td><td>MTA-STS policy ID</td></tr><tr><td><code>@</code></td><td>"site-verification=…" ownership proofs</td></tr></table>' } }] },
      { title: 'A verifier queries example.com TXT', focus: ['client', 'resolver', 'auth'], text: '<p>For example, a receiving mail server checking SPF, or a SaaS service checking that you really control the domain.</p>', actions: [L.ask, L.fwd] },
      { title: 'All TXT records at the name come back', focus: ['auth', 'resolver', 'client'], text: '<p>The client has to pick out the strings it cares about (e.g. those starting with <code>v=spf1</code>). Too many TXT records at the apex make responses large, which can lead to truncation and TCP fallback.</p>', deep: '<p>Services use underscore-prefixed names (<code>_dmarc</code>, <code>_acme-challenge</code>) so their records don\'t pile up at the apex. RFC 8552 created a registry for these names.</p>', actions: [L.back, L.ret] },
    ];
  };

  T.PTR = () => {
    const rev = '10.113.0.203.in-addr.arpa';
    const q = D.query({ src: C.ip4, dst: R.ip4, name: rev, type: 'PTR' });
    const qa = D.query({ src: R.ip4, dst: '198.51.100.7', name: rev, type: 'PTR', rd: 0 });
    const ra = D.response(qa, { aa: 1, an: [rr(rev, 3600, 'PTR', 'www.example.com.')] });
    const r = D.response(q, { ra: 1, an: [rr(rev, 3600, 'PTR', 'www.example.com.')] });
    return [
      { title: 'PTR: IP address → name (reverse DNS)', focus: ['client'], text: '<p>Reverse lookups turn an address back into a name. The octets are written <b>in reverse</b> under <code>in-addr.arpa</code>, so the DNS hierarchy (most significant part on the right) matches IP allocation (most significant part on the left).</p>',
        actions: [{ hl: ['ptr'] }, { overlay: { id: 'rv', at: 'bl', title: 'Building the query name', html: chips(['203', '0', '113', '10']) + '<div class="arrow-down">↓ reverse and append in-addr.arpa</div>' + chips(['10', '113', '0', '203', 'in-addr', 'arpa'], (i) => (i > 3 ? 'dim' : 'hot')) } }] },
      { title: 'Query 10.113.0.203.in-addr.arpa PTR', focus: ['client', 'resolver'], text: '<p>For example a web server writing logs, <code>traceroute</code>, or a mail server checking a connecting client.</p>', actions: [{ send: ['client', 'resolver'], pkt: q }] },
      { title: 'Delegated by whoever owns the IP block', focus: ['resolver', 'other'], text: '<p>The reverse zone <code>113.0.203.in-addr.arpa</code> is delegated along the address allocation chain (IANA → RIR → ISP → customer), <b>not</b> the domain-name chain. The operator of example.com may not control its PTR records at all; its ISP or cloud provider often does.</p>',
        deep: '<p>Reverse delegation follows octet boundaries (/8, /16, /24). For smaller blocks, RFC 2317 uses CNAMEs to delegate "classless" reverse zones. For IPv6, <code>ip6.arpa</code> uses one label per 4-bit nibble; see the IPv6 lesson.</p>',
        actions: [{ show: ['other'] }, { send: ['resolver', 'other'], pkt: qa }, { send: ['other', 'resolver'], pkt: ra }, { send: ['resolver', 'client'], pkt: r }, { badge: 'client', text: '→ www.example.com', tone: 'ok' }] },
      { title: 'Trust, but verify (FCrDNS)', focus: ['client'], text: '<p>Whoever controls the reverse zone can put <i>any</i> name in a PTR record. Careful software therefore does a <b>forward-confirmed</b> check: resolve <code>www.example.com</code> A and make sure it returns 203.0.113.10 again.</p>',
        actions: [{ overlay: { id: 'fc', at: 'bl', cls: 'ok', title: 'Forward-confirmed reverse DNS', html: '203.0.113.10 → PTR → www.example.com<br>www.example.com → A → 203.0.113.10 <span class="good">✓ match</span>' } }] },
    ];
  };

  T.SRV = () => {
    const L = lookup('_sips._tcp.example.com', 'SRV', [rr('_sips._tcp.example.com', 3600, 'SRV', '10 60 5061 sip1.example.com.')]);
    return [
      { title: 'SRV: service location with port', focus: ['auth'], text: '<p><b>SRV</b> records (RFC 2782) are named <code>_service._proto.domain</code> and return <b>priority, weight, port and target host</b>, so a client can discover the server and the port for a service.</p>',
        actions: [{ hl: ['srv'] }, { overlay: { id: 'f', at: 'bl', w: 420, title: 'Anatomy', html: '<pre>_sips._tcp  SRV  10   60    5061  sip1.example.com.\n                 prio weight port  target</pre>' } }] },
      { title: 'Query _sips._tcp.example.com SRV', focus: ['client', 'resolver', 'auth'], text: '<p>The client builds the query name from the service it wants to use.</p>', actions: [L.ask, L.fwd] },
      { title: 'Answer: connect to sip1.example.com:5061', focus: ['auth', 'resolver', 'client'], text: '<p>The client picks among records with the lowest priority, weighted randomly, then resolves the target\'s A/AAAA. See the animated VoIP flow in <a href="#connect">Using the answer → VoIP</a>.</p>', actions: [L.back, L.ret] },
    ];
  };

  T.CAA = () => {
    const q1 = D.query({ src: '198.51.100.200', dst: R.ip4, name: 'www.example.com', type: 'CAA' });
    const qa1 = D.query({ src: R.ip4, dst: A.ip4, name: 'www.example.com', type: 'CAA', rd: 0 });
    const ra1 = D.response(qa1, { aa: 1, ns: [rr('example.com', 3600, 'SOA', SOA)], note: 'NODATA: no CAA at www.example.com, so the CA climbs to the parent name.' });
    const r1 = D.response(q1, { ra: 1, ns: [rr('example.com', 3600, 'SOA', SOA)] });
    const L2 = lookup('example.com', 'CAA', [rr('example.com', 3600, 'CAA', '0 issue "letsencrypt.org"'), rr('example.com', 3600, 'CAA', '0 iodef "mailto:security@example.com"')], { client: 'ca', src: '198.51.100.200' });
    return [
      { title: 'CAA: which CAs may issue certificates', focus: ['auth', 'ca'], text: '<p><b>CAA</b> (Certification Authority Authorization, RFC 8659) lets a domain owner list the CAs allowed to issue certificates for it. Since 2017 every publicly trusted CA <b>must</b> check CAA before issuing.</p>',
        actions: [{ hl: ['caa'] }, { show: ['ca'] }, { badge: 'ca', text: 'request: cert for www.example.com', tone: 'info' }] },
      { title: 'CA checks www.example.com CAA', focus: ['ca', 'resolver', 'auth'], text: '<p>The CA first looks at the exact name. There are no CAA records there (NODATA)…</p>', actions: [{ send: ['ca', 'resolver'], pkt: q1 }, { send: ['resolver', 'auth'], pkt: qa1 }, { send: ['auth', 'resolver'], pkt: ra1 }, { send: ['resolver', 'ca'], pkt: r1 }] },
      { title: '…so it climbs to example.com CAA', focus: ['ca', 'resolver', 'auth'], text: '<p>The CA walks up the tree until it finds a CAA record set. At <code>example.com</code>: <code>0 issue "letsencrypt.org"</code>.</p>', actions: [L2.ask, L2.fwd, L2.back, L2.ret] },
      { title: 'Decision', focus: ['ca'], text: '<p>Only Let\'s Encrypt may issue. Any other CA must <b>refuse</b>. The <code>iodef</code> property gives an address for reporting refused requests, and <code>issuewild</code> controls wildcard certificates separately.</p>', deep: '<p>CAA is only as trustworthy as the DNS answer the CA receives, which is why CAs are encouraged to validate DNSSEC and to query from several network vantage points.</p>',
        actions: [{ overlay: { id: 'd', at: 'bl', title: 'Issuance check', html: '<table><tr><td>Let\'s Encrypt</td><td class="good">✓ may issue</td></tr><tr><td>Any other CA</td><td class="badc">✗ must refuse</td></tr></table>' } }, { badge: 'ca', text: 'issue allowed ✓', tone: 'ok' }] },
    ];
  };

  T.HTTPS = () => {
    const L = lookup('www.example.com', 'HTTPS', [rr('www.example.com', 3600, 'HTTPS', '1 . alpn=h3,h2 ipv4hint=203.0.113.10')]);
    return [
      { title: 'HTTPS / SVCB: how to connect', focus: ['auth'], text: '<p><b>SVCB</b> (type 64) and its HTTPS-specific form <b>HTTPS</b> (type 65), defined in RFC 9460, publish connection parameters: supported protocols (<code>alpn</code>), alternative port, IP hints, and <code>ech</code> keys for Encrypted Client Hello.</p>',
        actions: [{ hl: ['https'] }, { overlay: { id: 'f', at: 'bl', w: 400, title: 'Two modes', html: '<table><tr><th>AliasMode (priority 0)</th><td><code>example.com. HTTPS 0 cdn.provider.example.</code>: a CNAME-like alias that <b>is allowed at the apex</b></td></tr><tr><th>ServiceMode (≥1)</th><td><code>www HTTPS 1 . alpn=h3,h2</code>: endpoint plus parameters</td></tr></table>' } }] },
      { title: 'Query www.example.com HTTPS', focus: ['client', 'resolver', 'auth'], text: '<p>Browsers send this query in parallel with A/AAAA.</p>', actions: [L.ask, L.fwd] },
      { title: 'Answer: HTTP/3 available', focus: ['auth', 'resolver', 'client'], text: '<p>With <code>alpn=h3</code> the browser can use QUIC on the very first connection. Watch that flow in <a href="#connect">Using the answer → HTTP/3</a>.</p>', actions: [L.back, L.ret] },
    ];
  };

  T.DNSKEY = () => {
    const keys = [rr('example.com', 3600, 'DNSKEY', D.dnskey(K.ksk, true)), rr('example.com', 3600, 'DNSKEY', D.dnskey(K.zsk, false))];
    const sig = rr('example.com', 3600, 'RRSIG', D.rrsig('DNSKEY', 13, 2, 3600, K.ksk.tag, 'example.com'));
    const L = lookup('example.com', 'DNSKEY', [...keys, sig], { do: true, ad: true });
    return [
      { title: 'DNSKEY: the zone\'s public keys', focus: ['auth'], text: '<p>A signed zone publishes its public keys in <b>DNSKEY</b> records. Most zones use two roles:</p><ul><li><b>KSK</b> (Key Signing Key, flags <b>257</b>, SEP bit set) signs only the DNSKEY set. Its hash is published as the DS record in the parent.</li><li><b>ZSK</b> (Zone Signing Key, flags <b>256</b>) signs all the other records.</li></ul>',
        actions: [{ hl: ['dnskey'] }, { overlay: { id: 'f', at: 'bl', w: 380, title: 'DNSKEY RDATA', html: '<pre>257  3        13         mdss…\nflags protocol algorithm public key</pre>Algorithm 13 = ECDSA P-256 with SHA-256. Protocol is always 3.' } }] },
      { title: 'Query example.com DNSKEY (DO=1)', focus: ['client', 'resolver', 'auth'], text: '<p>The DO ("DNSSEC OK") bit in EDNS asks the server to include signatures.</p>', actions: [L.ask, L.fwd] },
      { title: 'Keys plus a signature by the KSK', focus: ['auth', 'resolver', 'client'], text: '<p>The DNSKEY RRset comes back with its <b>RRSIG made by the KSK</b>. A validator checks that the KSK matches the parent\'s DS record, then trusts the ZSK because the KSK signed it. The full chain is animated in the <a href="#dnssec">DNSSEC</a> lesson.</p>', deep: '<p>Splitting KSK and ZSK lets operators rotate the ZSK often without touching the parent. Many modern setups use a single Combined Signing Key (CSK) instead.</p>', actions: [L.back, L.ret] },
    ];
  };

  T.DS = () => {
    const ds = rr('example.com', 86400, 'DS', `${K.ksk.tag} 13 2 ${K.ds}`);
    const sig = rr('example.com', 86400, 'RRSIG', D.rrsig('DS', 13, 2, 86400, Wd.keys.com.zsk.tag, 'com'));
    const L = lookup('example.com', 'DS', [ds, sig], { do: true, ad: true, server: 'tld', serverIp: Wd.com.ip4, anote: 'The DS lives in the PARENT zone (com.) and is signed with the .com zone key.' });
    return [
      { title: 'DS: the link between parent and child', focus: ['tld'], text: '<p>The <b>DS</b> (Delegation Signer) record is stored in the <b>parent</b> zone. It contains a hash of the child\'s KSK. Because the parent signs it, a validator that trusts the parent can extend that trust to the child\'s key.</p>',
        actions: [{ hl: ['ds', 'del'] }, { show: ['tld'] }, { overlay: { id: 'f', at: 'bl', w: 400, title: 'DS RDATA', html: `<pre>${K.ksk.tag}   13        2           ${short(K.ds, 10)}\nkey tag algorithm digest type digest (SHA-256)</pre>digest = SHA-256(owner name ‖ DNSKEY RDATA of the KSK)` } }] },
      { title: 'Query example.com DS → asks the .com servers', focus: ['client', 'resolver', 'tld'], text: '<p>The resolver sends DS queries to the <i>parent\'s</i> servers. This is the one record type that belongs on the parent side of the zone cut.</p>', actions: [L.ask, L.fwd] },
      { title: 'DS signed by .com', focus: ['tld', 'resolver', 'client'], text: '<p>The domain owner uploads the DS through their registrar (or automatically with CDS/CDNSKEY, RFC 8078). If the DS and the child\'s KSK stop matching, for example after a botched key rollover, the whole domain becomes <b>bogus</b> for validating resolvers.</p>', actions: [L.back, L.ret] },
    ];
  };

  T.RRSIG = () => {
    const a = rr('www.example.com', 3600, 'A', Wd.web.ip4);
    const sig = rr('www.example.com', 3600, 'RRSIG', D.rrsig('A', 13, 3, 3600, K.zsk.tag, 'example.com'));
    const L = lookup('www.example.com', 'A', [a, sig], { do: true, ad: true });
    return [
      { title: 'RRSIG: a signature over an RRset', focus: ['auth'], text: '<p>Every signed <b>RRset</b> (all records with the same name, class and type) has an <b>RRSIG</b>. It covers the whole set, not individual records.</p>',
        actions: [{ hl: ['rrsig', 'wwwa'] }] },
      { title: 'Query www.example.com A with DO=1', focus: ['client', 'resolver', 'auth'], text: '<p>With the DO bit set, the authoritative server returns the RRSIG alongside the A record.</p>', actions: [L.ask, L.fwd] },
      { title: 'Signature fields', focus: ['auth', 'resolver', 'client'], text: '<p>The validator checks the signature using the DNSKEY that matches the <b>key tag</b> and <b>signer name</b>, and only accepts it inside the inception–expiration window. That window is why signers must re-sign regularly, and why clock skew can break validation.</p>', deep: '<p>The <b>labels</b> field (3 for www.example.com) lets a validator detect answers synthesized from a wildcard. The <b>original TTL</b> is signed, because the TTL itself decreases in caches.</p>',
        actions: [L.back, L.ret, { overlay: { id: 'f', at: 'bl', w: 420, title: 'RRSIG RDATA', html: `<table><tr><th>Type covered</th><td>A</td></tr><tr><th>Algorithm</th><td>13 (ECDSA P-256/SHA-256)</td></tr><tr><th>Labels</th><td>3</td></tr><tr><th>Original TTL</th><td>3600</td></tr><tr><th>Expiration / Inception</th><td>2026-10-24 / 2026-09-24</td></tr><tr><th>Key tag</th><td>${K.zsk.tag} (the ZSK)</td></tr><tr><th>Signer</th><td>example.com.</td></tr></table>` } }] },
    ];
  };

  T.NSEC = () => {
    const nsec1 = rr('mx2.example.com', 300, 'NSEC', 'ns1.example.com. A RRSIG NSEC');
    const nsec2 = rr('example.com', 300, 'NSEC', '_sips._tcp.example.com. A NS SOA MX TXT CAA RRSIG NSEC DNSKEY');
    const ns = [rr('example.com', 300, 'SOA', SOA), nsec1, rr('mx2.example.com', 300, 'RRSIG', D.rrsig('NSEC', 13, 3, 300, K.zsk.tag, 'example.com')), nsec2, rr('example.com', 300, 'RRSIG', D.rrsig('NSEC', 13, 2, 300, K.zsk.tag, 'example.com'))];
    const L = lookup('nope.example.com', 'A', [], { do: true, ad: true, rcode: 'NXDOMAIN', ns, anote: 'Authenticated denial: the NSEC records prove no name exists between mx2 and ns1, and no wildcard exists either.' });
    const order = ['example.com', '_sips._tcp', 'mx1', 'mx2', 'nope ✗', 'ns1', 'shop', 'www'];
    return [
      { title: 'Proving that something does NOT exist', focus: ['auth'], text: '<p>You can\'t sign an answer that doesn\'t exist, and signing NXDOMAIN responses on the fly would expose private keys and cost CPU. Instead, <b>NSEC</b> records chain every name in the zone in canonical order. Each one says "the next name after me is X".</p>',
        actions: [{ hl: ['nsec'] }, { overlay: { id: 'o', at: 'bl', w: 440, title: 'Canonical order of names in example.com', html: chips(order, (i) => (i === 4 ? 'bad' : i === 3 || i === 5 ? 'hot' : '')) } }] },
      { title: 'Query nope.example.com A', focus: ['client', 'resolver', 'auth'], text: '<p>The name doesn\'t exist.</p>', actions: [L.ask, L.fwd] },
      { title: 'NXDOMAIN + signed NSEC proof', focus: ['auth', 'resolver', 'client'], text: '<p><code>mx2.example.com NSEC ns1.example.com</code> proves that nothing exists between <i>mx2</i> and <i>ns1</i>, and <code>nope</code> would sort there. A second NSEC proves that no wildcard <code>*.example.com</code> exists. Both are signed, so the denial cannot be forged.</p>', actions: [L.back, L.ret] },
      { title: 'Zone walking → NSEC3', focus: ['auth'], text: '<p>Following the NSEC chain from one name to the next reveals <b>every name in the zone</b> ("zone walking"). <b>NSEC3</b> (RFC 5155) chains <i>hashes</i> of names instead, so the proof shows only that the hash of <code>nope.example.com</code> falls between two other hashes.</p>', deep: '<p>NSEC3 hashes can still be cracked offline with dictionaries, and extra iterations mainly slow down resolvers, so RFC 9276 recommends <b>0 iterations and no salt</b>. Signers that sign on the fly can also use "compact denial" (black lies) to avoid enumeration.</p>',
        actions: [{ overlay: { id: 'n3', at: 'bl', w: 460, title: 'NSEC3: a chain of hashes', html: `<div class="small">H(nope.example.com) = <span class="mono">8P2QK…</span></div>${chips(['2T7B4G…', '5KQH1L…', '8P2QK… ✗', 'B0R3NM…', 'K1V9T0…'], (i) => (i === 2 ? 'bad' : i === 1 || i === 3 ? 'hot' : ''))}<div class="small muted">The owner names are hashes, so walking the chain reveals no readable names.</div>` } }] },
    ];
  };

  const TYPES = [
    ['A', 'A: IPv4 address'], ['AAAA', 'AAAA: IPv6 address'], ['CNAME', 'CNAME: alias'], ['MX', 'MX: mail exchanger'], ['NS', 'NS: name server'],
    ['SOA', 'SOA: start of authority + zone transfer'], ['TXT', 'TXT: text / SPF / verification'], ['PTR', 'PTR: reverse DNS'], ['SRV', 'SRV: service locator'],
    ['CAA', 'CAA: CA authorization'], ['HTTPS', 'HTTPS / SVCB: service binding'], ['DNSKEY', 'DNSKEY: zone public keys'], ['DS', 'DS: delegation signer'],
    ['RRSIG', 'RRSIG: signatures'], ['NSEC', 'NSEC / NSEC3: authenticated denial'],
  ];

  DV.register({
    id: 'records',
    nav: 'Record types',
    title: 'DNS record types',
    icon: 'records',
    blurb: 'A, AAAA, CNAME, MX, NS, SOA, TXT, PTR, SRV, CAA, HTTPS/SVCB, DNSKEY, DS, RRSIG and NSEC/NSEC3, each with an animated lookup and its line in a real zone file.',
    intro: '<p>A zone is a set of <b>resource records</b>, each with a name, TTL, class, type and type-specific RDATA. Pick a type to see where it lives in the zone file, what a query for it looks like on the wire, and what uses it.</p>',
    options: [{ id: 'type', type: 'select', label: 'Record type', value: 'A', choices: TYPES }],
    build(o) {
      const t = o.type;
      const extra = {
        CNAME: { label: 'ns1.saas.example', sub: '198.51.100.8<br>(authoritative for saas.example)', icon: 'auth', tier: 'auth' },
        SOA: { label: 'ns2.example.net', sub: '198.51.100.9 (secondary)', icon: 'server', tier: 'auth' },
        PTR: { label: 'Reverse-zone server', sub: '198.51.100.7<br>113.0.203.in-addr.arpa', icon: 'auth', tier: 'tld' },
      }[t];
      const clientLabel = { MX: 'Sending mail server', TXT: 'Verifier', PTR: 'Log analyser', SRV: 'Softphone' }[t] || 'Client (dig)';
      const nodes = [
        { id: 'client', x: 110, y: 190, icon: t === 'MX' ? 'mailserver' : t === 'SRV' ? 'voip' : 'laptop', tier: 'client', label: clientLabel, sub: C.ip4, hidden: t === 'CAA' },
        { id: 'ca', x: 110, y: 190, icon: 'ca', tier: 'ca', label: "Let's Encrypt (CA)", sub: '198.51.100.200', hidden: true },
        { id: 'resolver', x: 430, y: 190, icon: 'resolver', tier: 'resolver', label: 'Recursive resolver', sub: R.ip4 },
        { id: 'auth', x: 800, y: 190, icon: 'auth', tier: 'auth', label: 'ns1.example.com', sub: `${A.ip4}<br>(authoritative)` },
        { id: 'tld', x: 560, y: 430, icon: 'tld', tier: 'tld', label: '.com TLD server', sub: `${Wd.com.name}<br>${Wd.com.ip4}`, hidden: true },
        Object.assign({ id: 'other', x: 800, y: 430, hidden: true }, extra || { label: '', icon: 'server' }),
      ];
      const links = [['client', 'resolver'], ['ca', 'resolver'], ['resolver', 'auth'], ['resolver', 'tld'], ['resolver', 'other'], ['auth', 'other']];
      return { nodes, links, steps: T[t](), panel: { title: `${DV.icon('zone')} Zone file & related zones`, html: zoneHtml },
        intro: `<b>${TYPES.find((x) => x[0] === t)[1]}</b>. Press <b>Play</b>; the matching zone-file lines light up on the right.` };
    },
  });
})();
