/* Section 5 — IPv4 vs IPv6: dual-stack lookups, DNS64/NAT64 and reverse DNS. */
(function () {
  'use strict';
  const DV = window.DV;
  const D = DV.dns, N = DV.net, Wd = DV.world;
  const rr = D.rr;
  const C = Wd.client, R = Wd.resolver, RT = Wd.root, A = Wd.auth, WEB = Wd.web;
  const chips = (arr, cls, delay) => `<div class="chips">${arr.map((x, i) => `<span class="chip ${cls ? cls(i) : ''}" style="animation-delay:${i * (delay || 60)}ms">${x}</span>`).join('')}</div>`;
  const bytes = (arr, cls) => `<div class="bytes ${cls}">${arr.map((b, i) => `<span style="animation-delay:${i * 45}ms">${D.hex2(b)}</span>`).join('')}</div>`;

  function dual() {
    const nodes = [
      { id: 'laptop', x: 110, y: 280, icon: 'laptop', tier: 'client', label: 'Dual-stack laptop', sub: `${C.ip4}<br>${C.ip6}` },
      { id: 'resolver', x: 450, y: 280, icon: 'resolver', tier: 'resolver', label: 'Recursive resolver', sub: `${R.ip4}<br>${R.ip6}` },
      { id: 'root', x: 850, y: 95, icon: 'root', tier: 'root', label: 'Root server', sub: `${RT.ip4}<br>${RT.ip6}` },
      { id: 'auth', x: 850, y: 280, icon: 'auth', tier: 'auth', label: 'ns1.example.com', sub: `${A.ip4}<br>${A.ip6}` },
      { id: 'web', x: 850, y: 465, icon: 'web', tier: 'web', label: 'www.example.com', sub: `${WEB.ip4}<br>${WEB.ip6}`, hidden: true },
    ];
    const links = [['laptop', 'resolver'], ['resolver', 'root'], ['resolver', 'auth'], ['laptop', 'web']];
    const qA = D.query({ v: 6, src: C.ip6, dst: R.ip6, name: 'www.example.com', type: 'A', note: 'An A query carried over IPv6. The transport has nothing to do with the record type being asked for.' });
    const qAAAA = D.query({ v: 6, src: C.ip6, dst: R.ip6, name: 'www.example.com', type: 'AAAA' });
    const qRoot = D.query({ v: 6, src: R.ip6, dst: RT.ip6, name: 'www.example.com', type: 'AAAA', rd: 0, note: 'The resolver reaches the root over IPv6 using its IPv6 address from the root hints.' });
    const rRoot = D.response(qRoot, {
      ns: [rr('com', 172800, 'NS', 'a.gtld-servers.net.'), rr('com', 172800, 'NS', 'b.gtld-servers.net.')],
      ar: [rr('a.gtld-servers.net', 172800, 'A', Wd.com.ip4), rr('a.gtld-servers.net', 172800, 'AAAA', Wd.com.ip6)],
      note: 'Glue for both address families: A and AAAA records for every TLD server.' });
    const qAuthA = D.query({ v: 4, src: R.ip4, dst: A.ip4, name: 'www.example.com', type: 'A', rd: 0, note: 'The resolver picked IPv4 transport for this server. Resolvers choose per server, often by measured RTT.' });
    const qAuthAAAA = D.query({ v: 4, src: R.ip4, dst: A.ip4, name: 'www.example.com', type: 'AAAA', rd: 0 });
    const rAuthA = D.response(qAuthA, { aa: 1, an: [rr('www.example.com', 3600, 'A', WEB.ip4)] });
    const rAuthAAAA = D.response(qAuthAAAA, { aa: 1, an: [rr('www.example.com', 3600, 'AAAA', WEB.ip6)] });
    const rA = D.response(qA, { ra: 1, an: [rr('www.example.com', 3600, 'A', WEB.ip4)] });
    const rAAAA = D.response(qAAAA, { ra: 1, an: [rr('www.example.com', 3600, 'AAAA', WEB.ip6)] });
    const S = [
      {
        title: 'Record type ≠ transport',
        focus: ['laptop', 'resolver'],
        text: '<p>Two different things are often confused:</p><ul><li><b>What you ask for</b>: an <b>A</b> record (IPv4 address) or an <b>AAAA</b> record (IPv6 address).</li><li><b>How the DNS packet travels</b>: over IPv4 or IPv6.</li></ul><p>All four combinations are valid. An IPv4-only host can look up AAAA records, and DNS servers reached over IPv6 answer A queries just the same.</p>',
        actions: [{ overlay: { id: 't', at: 'bl', title: 'All valid', html: '<table><tr><th></th><th>over IPv4</th><th>over IPv6</th></tr><tr><th>A?</th><td class="good">✓</td><td class="good">✓</td></tr><tr><th>AAAA?</th><td class="good">✓</td><td class="good">✓</td></tr></table>' } }],
      },
      {
        title: 'getaddrinfo(AF_UNSPEC): A and AAAA in parallel',
        focus: ['laptop', 'resolver'],
        text: '<p>A dual-stack host wants both kinds of address, so the stub sends <b>an A query and an AAAA query at the same time</b>, here over IPv6 transport. Click the packets and compare their IPv6 headers.</p>',
        deep: '<p>glibc sends both queries from the same socket back to back. Some broken middleboxes dropped the second one, which is why the <code>single-request</code> option exists in resolv.conf. An IPv4-only host may skip AAAA (glibc uses <code>AI_ADDRCONFIG</code> to decide).</p>',
        actions: [{ par: [{ send: ['laptop', 'resolver'], pkt: qA, bend: 55 }, { send: ['laptop', 'resolver'], pkt: qAAAA, bend: -10 }] }],
      },
      {
        title: 'Resolver → root over IPv6',
        focus: ['resolver', 'root'],
        text: '<p>All 13 root server identities have IPv6 addresses (for example a.root-servers.net = <code>2001:503:ba3e::2:30</code>). The referral contains <b>glue for both families</b>: A <i>and</i> AAAA records for the TLD servers.</p>',
        deep: '<p>An IPv6-only resolver can only follow a delegation if at least one of the zone\'s name servers has an AAAA record. A zone reachable only over IPv4 name servers is effectively invisible to IPv6-only resolvers.</p>',
        actions: [{ send: ['resolver', 'root'], pkt: qRoot }, { send: ['root', 'resolver'], pkt: rRoot }],
      },
      {
        title: 'Resolver → authoritative over IPv4',
        focus: ['resolver', 'auth'],
        text: '<p>(The .com step is skipped here.) For this server the resolver happens to use <b>IPv4 transport</b>, and asks for both the A and AAAA records. Either family could have been used; resolvers choose per server.</p>',
        actions: [{ par: [{ send: ['resolver', 'auth'], pkt: qAuthA, bend: 50 }, { send: ['resolver', 'auth'], pkt: qAuthAAAA, bend: -10 }] }],
      },
      {
        title: '4 bytes vs 16 bytes',
        focus: ['auth', 'resolver'],
        text: '<p>The A answer carries 4 bytes of RDATA and the AAAA answer 16 bytes. Otherwise the records are handled the same way: same TTL rules, same caching, same DNSSEC signing.</p>',
        actions: [
          { par: [{ send: ['auth', 'resolver'], pkt: rAuthA, bend: 50 }, { send: ['auth', 'resolver'], pkt: rAuthAAAA, bend: -10 }] },
          { overlay: { id: 'b', at: 'bl', w: 440, title: 'RDATA on the wire', html: `<div class="small"><b>A</b>: 203.0.113.10 (4 bytes)</div>${bytes(D.ipv4Bytes(WEB.ip4), 'v4')}<div class="small" style="margin-top:6px"><b>AAAA</b>: 2001:db8:113::10 (16 bytes)</div>${bytes(D.ipv6Bytes(WEB.ip6), 'v6')}` } },
        ],
      },
      {
        title: 'Both answers reach the laptop',
        focus: ['resolver', 'laptop'],
        text: '<p><code>getaddrinfo()</code> now has one IPv4 and one IPv6 address and must decide which to try first.</p>',
        actions: [{ par: [{ send: ['resolver', 'laptop'], pkt: rA, bend: 55 }, { send: ['resolver', 'laptop'], pkt: rAAAA, bend: -10 }] }],
      },
      {
        title: 'Address selection (RFC 6724)',
        focus: ['laptop'],
        text: '<p>The OS sorts the addresses using the default policy table in RFC 6724. With native global IPv6 on both ends, <b>IPv6 is preferred</b>. Rules include: prefer matching scope, avoid deprecated addresses, prefer the matching address family, and prefer the longest matching prefix.</p>',
        deep: '<p>Admins can change the order via <code>/etc/gai.conf</code> on Linux or <code>netsh interface ipv6 set prefixpolicy</code> on Windows. Dual-stack clients also use <b>Happy Eyeballs</b> (RFC 8305): they start the IPv6 connection first and, if it hasn\'t completed after about 250 ms, start IPv4 in parallel. The first to succeed wins, so a broken IPv6 path never causes a long hang.</p>',
        actions: [{ overlay: { id: 's', at: 'bl', title: 'Sorted destination list', html: `<table><tr><th>#</th><th>Address</th><th>Why</th></tr><tr><td>1</td><td class="mono good">${WEB.ip6}</td><td>global IPv6, precedence 40</td></tr><tr><td>2</td><td class="mono">${WEB.ip4}</td><td>IPv4 (::ffff:0:0/96), precedence 35</td></tr></table>` } }],
      },
      {
        title: 'Connect over IPv6',
        focus: ['laptop', 'web'],
        text: '<p>The TCP SYN goes to <code>[2001:db8:113::10]:443</code>. From here on it\'s the same TCP → TLS → HTTP flow as over IPv4, except that NAT is usually not needed with IPv6.</p>',
        actions: [{ show: ['web'] }, { send: ['laptop', 'web'], tone: 'gen', label: 'TCP SYN via IPv6', pkt: N.tcp('SYN', C.ip6, WEB.ip6, 50611, 443) }, { send: ['web', 'laptop'], tone: 'gen', pkt: N.tcp('SYN, ACK', WEB.ip6, C.ip6, 443, 50611) }, { link: ['laptop', 'web'], id: 'c', tone: 'gen', label: 'TCP over IPv6' }],
      },
    ];
    return { nodes, links, steps: S, intro: 'A dual-stack host asks for both A and AAAA records, and the DNS packets themselves may travel over either protocol.' };
  }

  function dns64() {
    const PH = '2001:db8:c1::23', D64 = '2001:db8:53::64', LEG = '203.0.113.99', NATV4 = '198.51.100.64';
    const SYN6 = D.embed64('64:ff9b::', LEG);
    const nodes = [
      { id: 'phone', x: 110, y: 280, icon: 'phone', tier: 'client', label: 'IPv6-only phone', sub: PH },
      { id: 'dns64', x: 470, y: 110, icon: 'resolver', tier: 'resolver', label: 'DNS64 resolver', sub: `${D64}<br>(also has IPv4)` },
      { id: 'auth', x: 860, y: 110, icon: 'auth', tier: 'auth', label: 'ns1.legacy.example', sub: '203.0.113.98<br>IPv4-only zone' },
      { id: 'nat64', x: 470, y: 440, icon: 'nat', tier: 'observer', label: 'NAT64 gateway', sub: `64:ff9b::/96 ⇄ ${NATV4}` },
      { id: 'srv', x: 860, y: 440, icon: 'web', tier: 'web', label: 'legacy.example', sub: `${LEG} (IPv4 only)` },
    ];
    const links = [['phone', 'dns64'], ['dns64', 'auth'], ['phone', 'nat64'], ['nat64', 'srv']];
    const groups = [{ x: 15, y: 18, w: 240, h: 525, label: 'IPv6-only network' }, { x: 740, y: 18, w: 245, h: 525, label: 'IPv4-only Internet' }];
    const q = D.query({ v: 6, src: PH, dst: D64, name: 'legacy.example', type: 'AAAA' });
    const q6 = D.query({ src: R.ip4, dst: '203.0.113.98', name: 'legacy.example', type: 'AAAA', rd: 0 });
    const r6 = D.response(q6, { aa: 1, ns: [rr('legacy.example', 3600, 'SOA', 'ns1.legacy.example. admin.legacy.example. 7 3600 900 604800 300')], note: 'NODATA: the name exists, but there is no AAAA record.' });
    const q4 = D.query({ src: R.ip4, dst: '203.0.113.98', name: 'legacy.example', type: 'A', rd: 0 });
    const r4 = D.response(q4, { aa: 1, an: [rr('legacy.example', 3600, 'A', LEG)] });
    const r = D.response(q, { ra: 1, an: [rr('legacy.example', 3600, 'AAAA', SYN6)], note: `SYNTHESIZED: ${SYN6} = well-known prefix 64:ff9b::/96 + the IPv4 address ${LEG} in hex. This record does not exist in the zone.` });
    const hex = D.ipv4Bytes(LEG).map(D.hex2);
    const S = [
      {
        title: 'An IPv6-only phone wants an IPv4-only site',
        focus: ['phone', 'dns64'],
        text: '<p>Many mobile networks give phones <b>only IPv6</b>, but <code>legacy.example</code> has no IPv6 at all. The phone asks its network\'s resolver for AAAA, as usual.</p>',
        actions: [{ send: ['phone', 'dns64'], pkt: q }],
      },
      {
        title: 'AAAA? → nothing (NODATA)',
        focus: ['dns64', 'auth'],
        text: '<p>The DNS64 resolver passes the AAAA query on. The zone has no AAAA record, so the answer is NOERROR with an empty answer section.</p>',
        actions: [{ send: ['dns64', 'auth'], pkt: q6 }, { send: ['auth', 'dns64'], pkt: r6 }, { badge: 'dns64', text: 'no AAAA', tone: 'warn' }],
      },
      {
        title: 'DNS64 falls back to A',
        focus: ['dns64', 'auth'],
        text: '<p>Instead of returning "no IPv6 address", the DNS64 resolver asks for the <b>A record</b> and gets <code>203.0.113.99</code>.</p>',
        actions: [{ send: ['dns64', 'auth'], pkt: q4 }, { send: ['auth', 'dns64'], pkt: r4 }],
      },
      {
        title: 'Synthesize an IPv6 address',
        focus: ['dns64'],
        text: `<p>DNS64 (RFC 6147) embeds the 32-bit IPv4 address in a /96 IPv6 prefix that routes to the NAT64 gateway, here the well-known prefix <code>64:ff9b::/96</code> (RFC 6052).</p>`,
        actions: [{ overlay: { id: 'syn', at: 'center', w: 400, title: 'Synthesis', html: `${chips(D.ipv4Bytes(LEG).map(String))}<div class="arrow-down">↓ each octet to hex</div>${chips(hex, () => 'hot')}<div class="arrow-down">↓ append to 64:ff9b::/96</div>${chips(['64:ff9b::', hex[0] + hex[1], ':', hex[2] + hex[3]], (i) => (i === 0 ? 'dim' : 'ok'), 120)}<div class="mono small" style="margin-top:4px">= <b>${SYN6}</b></div>` } }],
      },
      {
        title: 'Phone receives a synthesized AAAA',
        focus: ['dns64', 'phone'],
        text: '<p>The phone thinks it received an ordinary AAAA record. It doesn\'t need to know anything about NAT64.</p>',
        deep: '<p>A synthesized record isn\'t signed, so it would fail DNSSEC validation on the device. RFC 6147 therefore skips synthesis when the client sets both DO and CD, i.e. when it validates for itself. Devices can learn the NAT64 prefix by querying <code>ipv4only.arpa</code> (RFC 7050) and synthesize addresses locally.</p>',
        actions: [{ send: ['dns64', 'phone'], pkt: r }, { badge: 'phone', text: `AAAA ${SYN6}`, tone: 'ok' }],
      },
      {
        title: 'IPv6 packet → NAT64 → IPv4 packet',
        focus: ['phone', 'nat64', 'srv'],
        text: `<p>The phone sends a normal IPv6 SYN to <code>[${SYN6}]:443</code>. Routing sends 64:ff9b::/96 to the <b>NAT64 gateway</b>, which extracts the IPv4 address from the low 32 bits and forwards an <b>IPv4</b> packet from its own address <code>${NATV4}</code>, keeping per-flow state just like NAT44.</p>`,
        actions: [
          { send: ['phone', 'nat64'], tone: 'gen', label: `SYN → [${SYN6}]`, pkt: N.tcp('SYN', PH, SYN6, 50931, 443, { note: 'IPv6 packet: the destination is inside the NAT64 prefix.' }) },
          { badge: 'nat64', text: 'translate IPv6 → IPv4 (RFC 7915)', tone: 'info' },
          { send: ['nat64', 'srv'], tone: 'gen', label: `SYN → ${LEG}`, pkt: N.tcp('SYN', NATV4, LEG, 61022, 443, { note: 'The same SYN rebuilt as an IPv4 packet. The server sees the NAT64 gateway as the client.' }) },
        ],
      },
      {
        title: 'Replies are translated back',
        focus: ['srv', 'nat64', 'phone'],
        text: '<p>The IPv4 server answers the gateway, which maps the reply back into IPv6. Most apps work without changes. The exceptions are apps that use <b>IPv4 literals</b> rather than names, and for those devices add <b>464XLAT</b> (CLAT, RFC 6877).</p>',
        actions: [
          { send: ['srv', 'nat64'], tone: 'gen', pkt: N.tcp('SYN, ACK', LEG, NATV4, 443, 61022) },
          { send: ['nat64', 'phone'], tone: 'gen', pkt: N.tcp('SYN, ACK', SYN6, PH, 443, 50931) },
          { link: ['phone', 'nat64'], id: 'a', tone: 'gen', label: 'IPv6' },
          { link: ['nat64', 'srv'], id: 'b', tone: 'gen', label: 'IPv4' },
        ],
      },
    ];
    return { nodes, links, groups, steps: S, intro: 'How an IPv6-only device reaches an IPv4-only server: DNS <i>synthesizes</i> an IPv6 address, and a NAT64 gateway translates the packets.' };
  }

  function reverse() {
    const v4 = WEB.ip4, v6 = WEB.ip6;
    const rev4 = D.reverse4(v4), rev6 = D.reverse6(v6);
    const nib = D.ipv6Expand(v6).join('').split('');
    const nodes = [
      { id: 'admin', x: 110, y: 280, icon: 'laptop', tier: 'client', label: 'Admin running dig -x', sub: C.ip4 },
      { id: 'resolver', x: 450, y: 280, icon: 'resolver', tier: 'resolver', label: 'Recursive resolver', sub: R.ip4 },
      { id: 'rev4', x: 850, y: 120, icon: 'auth', tier: 'tld', label: '113.0.203.in-addr.arpa', sub: 'reverse zone for 203.0.113.0/24' },
      { id: 'rev6', x: 850, y: 440, icon: 'auth', tier: 'auth', label: '3.1.1.0.8.b.d.0.1.0.0.2.ip6.arpa', sub: 'reverse zone for 2001:db8:113::/48' },
    ];
    const q4 = D.query({ src: C.ip4, dst: R.ip4, name: rev4, type: 'PTR' });
    const q4a = D.query({ src: R.ip4, dst: '198.51.100.7', name: rev4, type: 'PTR', rd: 0 });
    const r4a = D.response(q4a, { aa: 1, an: [rr(rev4, 3600, 'PTR', 'www.example.com.')] });
    const r4 = D.response(q4, { ra: 1, an: [rr(rev4, 3600, 'PTR', 'www.example.com.')] });
    const q6 = D.query({ src: C.ip4, dst: R.ip4, name: rev6, type: 'PTR' });
    const q6a = D.query({ src: R.ip4, dst: '198.51.100.17', name: rev6, type: 'PTR', rd: 0 });
    const r6a = D.response(q6a, { aa: 1, an: [rr(rev6, 3600, 'PTR', 'www.example.com.')] });
    const r6 = D.response(q6, { ra: 1, an: [rr(rev6, 3600, 'PTR', 'www.example.com.')], note: 'The query name has 34 labels, and 32 of them are single hex nibbles.' });
    const S = [
      {
        title: 'IPv4 reverse: reverse the octets',
        focus: ['admin'],
        text: '<p><code>dig -x 203.0.113.10</code> turns the address into a name under <code>in-addr.arpa</code>, reversing the four octets so that the most significant part sits closest to the root.</p>',
        actions: [{ overlay: { id: 'v4', at: 'tr', w: 380, title: 'in-addr.arpa', html: `${chips(v4.split('.'))}<div class="arrow-down">↓ reverse</div>${chips([...v4.split('.').reverse(), 'in-addr', 'arpa'], (i) => (i > 3 ? 'dim' : 'hot'))}<div class="small muted">4 labels, one per octet (8 bits)</div>` } }],
      },
      {
        title: 'Query the PTR record',
        focus: ['admin', 'resolver', 'rev4'],
        text: '<p>The reverse tree is delegated along address allocation: IANA → RIR (ARIN, RIPE, APNIC…) → ISP → customer. Delegations fall on octet boundaries (/8, /16, /24).</p>',
        deep: '<p>For blocks smaller than a /24, RFC 2317 "classless" delegation uses CNAMEs from the parent\'s reverse zone into a customer-controlled zone.</p>',
        actions: [{ send: ['admin', 'resolver'], pkt: q4 }, { send: ['resolver', 'rev4'], pkt: q4a }, { send: ['rev4', 'resolver'], pkt: r4a }, { send: ['resolver', 'admin'], pkt: r4 }, { badge: 'admin', text: '→ www.example.com', tone: 'ok' }],
      },
      {
        title: 'IPv6 reverse: expand to 32 nibbles',
        focus: ['admin'],
        text: '<p>First the <code>::</code> shorthand is expanded and every group padded to four hex digits, giving 32 hex <b>nibbles</b> (4 bits each).</p>',
        actions: [{ overlay: { id: 'v6', at: 'tr', w: 460, title: '2001:db8:113::10 expanded', html: `<div class="mono small">${D.ipv6Expand(v6).join(':')}</div>${chips(nib, (i) => (Math.floor(i / 4) % 2 ? 'hot' : ''), 25)}` } }],
      },
      {
        title: '…then reverse them, one label per nibble',
        focus: ['admin'],
        text: '<p>The nibbles are reversed and dot-separated under <code>ip6.arpa</code>. That gives a 72-character name with 32 labels, compared with 4 labels for IPv4.</p>',
        actions: [{ overlay: { id: 'v6r', at: 'tr', w: 460, title: 'ip6.arpa name', html: `${chips([...nib.slice().reverse(), 'ip6', 'arpa'], (i) => (i >= 32 ? 'dim' : i >= 20 ? 'hot' : ''), 25)}<div class="small muted">The highlighted nibbles are the /48 prefix 2001:0db8:0113, which becomes the delegated zone.</div>` } }],
      },
      {
        title: 'Query the IPv6 PTR record',
        focus: ['admin', 'resolver', 'rev6'],
        text: '<p>Delegation happens on <b>nibble</b> boundaries (every 4 bits), so a /48 customer gets the zone <code>3.1.1.0.8.b.d.0.1.0.0.2.ip6.arpa</code>.</p>',
        actions: [{ send: ['admin', 'resolver'], pkt: q6 }, { send: ['resolver', 'rev6'], pkt: q6a }, { send: ['rev6', 'resolver'], pkt: r6a }, { send: ['resolver', 'admin'], pkt: r6 }, { badge: 'admin', text: '→ www.example.com', tone: 'ok' }],
      },
      {
        title: 'Comparing the two',
        focus: ['rev4', 'rev6'],
        text: '<p>A single IPv6 /64 subnet has 2<sup>64</sup> addresses, so nobody writes PTR records for all of them. ISPs either leave IPv6 reverse DNS empty, synthesize answers on the fly, or populate only their servers. Mail servers sending over IPv6 still need a correct PTR to be accepted.</p>',
        actions: [{ overlay: { id: 'cmp', at: 'bl', w: 460, title: 'in-addr.arpa vs ip6.arpa', html: '<table><tr><th></th><th>IPv4</th><th>IPv6</th></tr><tr><td>Label unit</td><td>octet (8 bits)</td><td>nibble (4 bits)</td></tr><tr><td>Labels per address</td><td>4</td><td>32</td></tr><tr><td>Delegation boundaries</td><td>/8 /16 /24 (+RFC 2317)</td><td>any multiple of 4 bits</td></tr><tr><td>Typical coverage</td><td>most addresses</td><td>servers only; often empty or synthesized</td></tr></table>' } }],
      },
    ];
    return { nodes, links: [['admin', 'resolver'], ['resolver', 'rev4'], ['resolver', 'rev6']], steps: S, intro: 'Reverse DNS for IPv4 (in-addr.arpa, per octet) compared with IPv6 (ip6.arpa, per nibble).' };
  }

  DV.register({
    id: 'ipv6',
    nav: 'IPv4 vs IPv6',
    title: 'IPv4 vs IPv6 resolution',
    icon: 'ipv6',
    blurb: 'A vs AAAA, DNS transport vs record type, dual-stack address selection, DNS64/NAT64 for IPv6-only networks, and in-addr.arpa vs ip6.arpa.',
    intro: '<p>DNS is mostly neutral about IP versions: <b>A</b> and <b>AAAA</b> are just two record types, and either can be fetched over either protocol. The interesting parts are how dual-stack hosts choose, how IPv6-only networks reach the IPv4 Internet, and how reverse DNS differs.</p>',
    options: [{ id: 'mode', type: 'segmented', label: 'Scenario', value: 'dual', choices: [['dual', 'Dual-stack lookup'], ['dns64', 'IPv6-only + DNS64/NAT64'], ['reverse', 'Reverse DNS v4 vs v6']] }],
    build(o) {
      return o.mode === 'dns64' ? dns64() : o.mode === 'reverse' ? reverse() : dual();
    },
  });
})();
