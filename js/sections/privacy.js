/* Section 7 — Privacy: plaintext Do53 vs DNS-over-TLS vs DNS-over-HTTPS, and the SNI leak (ECH). */
(function () {
  'use strict';
  const DV = window.DV;
  const D = DV.dns, N = DV.net, Wd = DV.world;
  const rr = D.rr;
  const C = Wd.client, A = Wd.auth, WEB = Wd.web;
  const RES = { name: 'dns.resolver.example', ip4: '198.51.100.53' };

  const panel = `<table class="ptable">
    <tr><th>Observer on the Wi-Fi / ISP link can see…</th><th></th></tr>
    <tr data-k="p-transport"><td>Traffic to the resolver</td><td>—</td></tr>
    <tr data-k="p-q"><td>DNS question</td><td>—</td></tr>
    <tr data-k="p-a"><td>DNS answer</td><td>—</td></tr>
    <tr data-k="p-mod"><td>Could modify the DNS answer</td><td>—</td></tr>
    <tr data-k="p-sni"><td>Site name in TLS SNI</td><td>—</td></tr>
    <tr data-k="p-ip"><td>Destination IP of the site</td><td>—</td></tr>
  </table><div class="pnote">Red = leaked to the observer, green = hidden, amber = partly revealed.</div>`;

  DV.register({
    id: 'privacy',
    nav: 'Privacy: DoT & DoH',
    title: 'DNS privacy: Do53 vs DoT vs DoH',
    icon: 'lock',
    blurb: 'Classic DNS is plaintext. See exactly what a Wi-Fi or ISP observer learns with UDP/53, DNS over TLS (853) and DNS over HTTPS (443), and why SNI and ECH matter too.',
    intro: '<p>Classic DNS ("Do53") travels as <b>plaintext UDP</b>. Anyone on the path can read, log or change it. <b>DoT</b> (RFC 7858) and <b>DoH</b> (RFC 8484) encrypt the connection between your device and the resolver. But what does that actually hide, and what does it not?</p>',
    options: [
      { id: 'tr', type: 'segmented', label: 'DNS transport', value: 'do53', choices: [['do53', 'Do53 (UDP 53)'], ['dot', 'DoT (TLS 853)'], ['doh', 'DoH (HTTPS 443)']] },
      { id: 'ech', type: 'check', label: 'Encrypted Client Hello (ECH)', value: false },
    ],
    build(o) {
      const enc = o.tr !== 'do53';
      const port = { do53: 53, dot: 853, doh: 443 }[o.tr];
      const nodes = [
        { id: 'laptop', x: 95, y: 290, icon: 'laptop', tier: 'client', label: 'Your laptop', sub: C.ip4 },
        { id: 'eye', x: 320, y: 290, icon: 'eye', tier: 'observer', label: 'Wi-Fi / ISP observer', sub: 'on the path' },
        { id: 'resolver', x: 600, y: 150, icon: 'resolver', tier: 'resolver', label: 'Public resolver', sub: `${RES.name}<br>${RES.ip4}` },
        { id: 'auth', x: 880, y: 90, icon: 'auth', tier: 'auth', label: 'ns1.example.com', sub: A.ip4 },
        { id: 'web', x: 880, y: 440, icon: 'web', tier: 'web', label: 'www.example.com', sub: `${WEB.ip4} (on a CDN)` },
      ];
      const links = [['laptop', 'eye'], ['eye', 'resolver'], ['resolver', 'auth'], ['eye', 'web']];
      const sp = 49321;
      const qIn = D.query({ src: C.ip4, dst: RES.ip4, name: 'www.example.com', type: 'A', tcp: enc, sport: sp, dport: port });
      const rIn = D.response(qIn, { ra: 1, an: [rr('www.example.com', 300, 'A', WEB.ip4)] });
      if (o.tr === 'doh') {
        qIn.layers = [{ name: 'HTTP/2 request', fields: [[':method', 'POST'], [':authority', RES.name], [':path', '/dns-query'], ['content-type', 'application/dns-message'], ['accept', 'application/dns-message']] }];
        rIn.layers = [{ name: 'HTTP/2 response', fields: [[':status', '200'], ['content-type', 'application/dns-message'], ['cache-control', 'max-age=300']] }];
      }
      const wrap = (p, dir) => D.encrypted(p, {
        proto: 'TCP', sport: dir ? sp : port, dport: dir ? port : sp, encName: o.tr === 'doh' ? 'HTTPS (TLS 1.3)' : 'TLS 1.3',
        summary: `TLS Application Data → ${dir ? RES.ip4 + ':' + port : C.ip4} (${o.tr === 'doh' ? 'DoH' : 'DoT'})`,
        label: dir ? 'DNS query' : 'DNS answer',
        note: 'Encrypted. The observer sees only the IP addresses, the port, the packet sizes and the timing.',
      });
      const qUp = D.query({ src: RES.ip4, dst: A.ip4, name: 'www.example.com', type: 'A', rd: 0, note: 'Resolver → authoritative traffic is still plaintext UDP/53 in almost all deployments.' });
      const rUp = D.response(qUp, { aa: 1, an: [rr('www.example.com', 300, 'A', WEB.ip4)] });
      const S = [];

      if (enc) {
        S.push({
          title: o.tr === 'dot' ? 'Open a TLS session to port 853' : 'Open an HTTPS connection to port 443',
          focus: ['laptop', 'eye', 'resolver'],
          text: o.tr === 'dot'
            ? '<p>DoT uses a dedicated port, <b>853</b>. The laptop does a TCP and TLS handshake with the resolver and verifies its certificate (<code>dns.resolver.example</code>). From now on DNS messages travel inside the tunnel, framed exactly like DNS over TCP.</p>'
            : '<p>DoH sends DNS messages as ordinary <b>HTTPS</b> requests to <code>https://dns.resolver.example/dns-query</code> on port <b>443</b>, the same port as all web traffic. Browsers often run DoH themselves, bypassing the OS resolver.</p>',
          deep: o.tr === 'dot'
            ? '<p>A dedicated port makes DoT easy to identify, and easy to block. Android\'s "Private DNS" uses DoT. Without certificate authentication ("opportunistic" mode), DoT protects only against passive observers.</p>'
            : '<p>One HTTP/2 or HTTP/3 connection can carry many concurrent queries. Networks can signal "please don\'t use DoH here" with the canary domain <code>use-application-dns.net</code>, and resolvers can advertise encrypted endpoints with DDR (RFC 9462).</p>',
          actions: [
            { send: ['laptop', 'resolver'], via: ['eye'], tone: 'gen', pkt: N.tcp('SYN', C.ip4, RES.ip4, sp, port) },
            { send: ['laptop', 'resolver'], via: ['eye'], tone: 'tls', pkt: N.tls('ClientHello', C.ip4, RES.ip4, sp, port, [['server_name (SNI)', RES.name], ['ALPN', o.tr === 'doh' ? 'h2' : 'dot']]) },
            { send: ['resolver', 'laptop'], via: ['eye'], tone: 'tls', pkt: N.tls('ServerHello + {Certificate}', RES.ip4, C.ip4, port, sp, [['{Certificate}', 'SAN = ' + RES.name]]) },
            { link: ['laptop', 'resolver'], id: 'tun', tone: 'enc', label: o.tr === 'dot' ? '🔒 DoT :853' : '🔒 DoH :443', dy: -22 },
            { badge: 'eye', text: o.tr === 'dot' ? `sees: TLS to ${RES.ip4}:853 → "that's DNS"` : `sees: HTTPS to ${RES.ip4}:443`, tone: 'warn' },
            { mark: { 'p-transport': 'warn' } },
            { panelHtml: { 'p-transport': `<td>Traffic to the resolver</td><td>${o.tr === 'dot' ? 'port 853 = DNS, clearly identifiable' : 'HTTPS to a known resolver IP'}</td>` } },
          ],
        });
      }

      S.push({
        title: enc ? 'The query travels encrypted' : 'The query travels in plaintext',
        focus: ['laptop', 'eye', 'resolver'],
        text: enc
          ? '<p>The DNS query is inside the encrypted session. The observer sees a small TLS record (its size and timing) but <b>not the name</b>. Click the packet: the outer layer is ciphertext, and you can reveal what only the two endpoints can read.</p>'
          : '<p>A standard UDP/53 query leaves the laptop. Every router, Wi-Fi hotspot and ISP along the path can read <code>www.example.com</code> directly from the packet. Many ISPs log these queries, and some sell or use the data.</p>',
        actions: [
          { send: ['laptop', 'resolver'], via: ['eye'], pkt: enc ? wrap(qIn, true) : qIn },
          enc ? { badge: 'eye', text: 'sees: ~100 bytes of ciphertext', tone: 'ok' } : { badge: 'eye', text: '👁 reads: "www.example.com A?"', tone: 'bad' },
          { mark: { 'p-q': enc ? 'ok' : 'bad', 'p-transport': enc ? (o.tr === 'dot' ? 'warn' : 'warn') : 'bad' } },
          { panelHtml: Object.assign({ 'p-q': `<td>DNS question</td><td>${enc ? 'hidden' : 'www.example.com (A)'}</td>` }, enc ? {} : { 'p-transport': '<td>Traffic to the resolver</td><td>UDP 53: plaintext DNS</td>' }) },
        ],
      });

      S.push({
        title: 'The resolver still sees everything',
        focus: ['resolver', 'auth'],
        text: '<p>Encryption protects the <i>path</i>, not the endpoint. The <b>resolver</b> decrypts and reads every query, so you are moving your trust from the local network to the resolver operator (check its logging policy). Its query to the authoritative server is usually <b>plaintext</b> again.</p>',
        deep: '<p>Mitigations: QNAME minimisation limits what root and TLD servers see. Oblivious DoH (ODoH, RFC 9230) adds a proxy so that no single party sees both your IP address and your query. Encrypting resolver-to-authoritative traffic is still experimental (RFC 9539).</p>',
        actions: [
          { badge: 'resolver', text: 'sees: your IP + www.example.com', tone: 'warn' },
          { send: ['resolver', 'auth'], pkt: qUp },
          { send: ['auth', 'resolver'], pkt: rUp },
        ],
      });

      S.push({
        title: enc ? 'The answer returns encrypted' : 'The answer returns in plaintext',
        focus: ['resolver', 'eye', 'laptop'],
        text: enc
          ? '<p>The answer is encrypted and <b>integrity-protected</b> by TLS, so an on-path attacker can neither read nor alter it. (DNSSEC protects the data itself end to end; TLS protects this one hop.)</p>'
          : '<p>The observer reads the answer too, and could <b>replace it</b>: forging a UDP reply is trivial for someone who is already on the path. Some networks do exactly this to redirect or censor sites.</p>',
        actions: [
          { send: ['resolver', 'laptop'], via: ['eye'], pkt: enc ? wrap(rIn, false) : rIn },
          enc ? { badge: 'eye', text: 'cannot read or modify ✓', tone: 'ok' } : { badge: 'eye', text: '👁 reads: 203.0.113.10 (could forge it)', tone: 'bad' },
          { mark: { 'p-a': enc ? 'ok' : 'bad', 'p-mod': enc ? 'ok' : 'bad' } },
          { panelHtml: { 'p-a': `<td>DNS answer</td><td>${enc ? 'hidden' : '203.0.113.10'}</td>`, 'p-mod': `<td>Could modify the DNS answer</td><td>${enc ? 'no (TLS integrity)' : 'yes (unless DNSSEC)'}</td>` } },
        ],
      });

      S.push({
        title: o.ech ? 'TLS to the website: ECH hides the name' : 'But then… the name leaks in TLS SNI',
        focus: ['laptop', 'eye', 'web'],
        text: o.ech
          ? '<p>With <b>Encrypted Client Hello</b> the real ClientHello, including the SNI <code>www.example.com</code>, is encrypted with a public key published in the site\'s <b>HTTPS DNS record</b> (the <code>ech=</code> parameter). The observer only sees the outer SNI of the CDN\'s shared front end.</p>'
          : '<p>The browser now connects to the website, and its TLS ClientHello carries <b>SNI = www.example.com in plaintext</b>. Encrypting DNS on its own doesn\'t hide which site you visit. The destination IP address also gives it away, unless the site shares its IP with many others on a CDN.</p>',
        deep: '<p>ECH (the TLS Encrypted Client Hello extension) only works when many sites sit behind one "client-facing server", as on large CDNs, which provides the anonymity set. It depends on DNS delivering the ECH config, which is one more reason to use encrypted and validated DNS.</p>',
        actions: [
          { send: ['laptop', 'web'], via: ['eye'], tone: 'tls', pkt: N.tls('ClientHello', C.ip4, WEB.ip4, 50514, 443, o.ech
            ? [['outer server_name', 'cdn-frontend.example'], ['encrypted_client_hello', '🔒 inner ClientHello (SNI www.example.com), encrypted to the ECH key from DNS']]
            : [['server_name (SNI)', '<b>www.example.com</b> ← plaintext'], ['ALPN', 'h2, http/1.1']]) },
          o.ech ? { badge: 'eye', text: 'sees SNI: cdn-frontend.example', tone: 'ok' } : { badge: 'eye', text: '👁 reads SNI: www.example.com', tone: 'bad' },
          { mark: { 'p-sni': o.ech ? 'ok' : 'bad', 'p-ip': 'warn' } },
          { panelHtml: { 'p-sni': `<td>Site name in TLS SNI</td><td>${o.ech ? 'hidden (ECH)' : 'www.example.com'}</td>`, 'p-ip': '<td>Destination IP of the site</td><td>203.0.113.10 (shared CDN IP?)</td>' } },
        ],
      });

      S.push({
        title: 'Summary: what each option protects',
        focus: ['eye'],
        text: `<p>You are viewing <b>${{ do53: 'Do53', dot: 'DoT', doh: 'DoH' }[o.tr]}${o.ech ? ' + ECH' : ''}</b>. Try the other options above and compare the observer panel on the right. Full privacy from the local network needs <b>encrypted DNS <i>and</i> ECH</b>. Even then the resolver sees your queries, and the site sees your IP address.</p>`,
        actions: [{ overlay: { id: 'sum', at: 'bl', w: 470, title: 'Comparison', html: '<table><tr><th></th><th>Do53</th><th>DoT</th><th>DoH</th></tr><tr><td>Port</td><td>53 UDP/TCP</td><td>853 TCP</td><td>443 TCP/QUIC</td></tr><tr><td>Query hidden from path</td><td class="badc">no</td><td class="good">yes</td><td class="good">yes</td></tr><tr><td>Tamper-proof on path</td><td class="badc">no</td><td class="good">yes</td><td class="good">yes</td></tr><tr><td>Easy to spot / block</td><td>—</td><td class="warnc">yes (port)</td><td class="good">hard</td></tr><tr><td>Typical client</td><td>OS stub</td><td>Android, stubby</td><td>browsers, iOS/macOS</td></tr></table>' } }],
      });

      return { nodes, links, steps: S, panel: { title: `${DV.icon('eye')} What the observer learns`, html: panel },
        intro: `Resolving and visiting <code>www.example.com</code> using <b>${{ do53: 'plaintext Do53', dot: 'DNS over TLS', doh: 'DNS over HTTPS' }[o.tr]}</b>${o.ech ? ' with ECH' : ''}. Watch what the pink observer can read.` };
    },
  });
})();
