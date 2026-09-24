/* Section 2 — Using the answer: web page load (TCP/TLS/HTTP, CDN), HTTP/3 via HTTPS RR, email via MX, services via SRV. */
(function () {
  'use strict';
  const DV = window.DV;
  const D = DV.dns, N = DV.net, Wd = DV.world;
  const rr = D.rr;
  const C = Wd.client, R = Wd.resolver;

  /* ------------------------------------------------------------ web page */
  function web(o) {
    const WEB = Wd.web.ip4, CDN = Wd.cdn.ip4;
    const sp = 50514, sp2 = 50522;
    const nodes = [
      { id: 'browser', x: 110, y: 290, icon: 'browser', tier: 'client', label: 'Browser', sub: C.ip4 },
      { id: 'resolver', x: 450, y: 90, icon: 'resolver', tier: 'resolver', label: 'Recursive resolver', sub: R.ip4, size: 'sm' },
      { id: 'web', x: 840, y: 175, icon: 'web', tier: 'web', label: 'www.example.com (origin)', sub: WEB },
      { id: 'cdn', x: 840, y: 430, icon: 'cdn', tier: 'auth', label: 'CDN edge (nearest PoP)', sub: CDN, hidden: true },
    ];
    const links = [['browser', 'resolver'], ['browser', 'web'], ['browser', 'cdn']];
    const S = [];
    S.push({
      title: 'DNS gave us an address, not a connection',
      focus: ['browser'],
      text: '<p>From the previous lesson the browser knows <code>www.example.com → 203.0.113.10</code>. Now it has to reach that address: a <b>TCP</b> connection, then <b>TLS</b> for encryption and authentication, then <b>HTTP</b>.</p>',
      actions: [{ badge: 'browser', text: 'www.example.com → 203.0.113.10', tone: 'ok' }, { lookup: 'reset' }],
    });
    S.push({
      title: 'TCP three-way handshake',
      focus: ['browser', 'web'],
      text: '<p><b>SYN → SYN-ACK → ACK.</b> The two sides agree on initial sequence numbers and options (MSS, window scaling, SACK). This costs <b>one round trip</b> before any data can flow.</p>',
      deep: '<p>The destination port (443) comes from the URL scheme, not from DNS. The only DNS input is the IP address. (SRV and HTTPS records <i>can</i> carry ports; see the other scenarios.)</p>',
      actions: [
        { send: ['browser', 'web'], pkt: N.tcp('SYN', C.ip4, WEB, sp, 443), tone: 'gen', ms: 20 },
        { send: ['web', 'browser'], pkt: N.tcp('SYN, ACK', WEB, C.ip4, 443, sp), tone: 'gen', ms: 20 },
        { send: ['browser', 'web'], pkt: N.tcp('ACK', C.ip4, WEB, sp, 443), tone: 'gen', ms: 0, dur: 700 },
        { link: ['browser', 'web'], id: 'c1', tone: 'gen', label: 'TCP :443' },
      ],
    });
    S.push({
      title: 'TLS ClientHello: the name appears again (SNI)',
      focus: ['browser', 'web'],
      text: '<p>The browser starts a TLS 1.3 handshake. Its ClientHello carries the <b>Server Name Indication</b> <code>www.example.com</code>, the same name you resolved. One IP address can host thousands of sites, so the server needs SNI to choose the right certificate.</p><p>SNI is sent <b>in plaintext</b>, so anyone on the path can read it (see the Privacy lesson and ECH).</p>',
      actions: [
        { send: ['browser', 'web'], tone: 'tls', ms: 20, pkt: N.tls('ClientHello', C.ip4, WEB, sp, 443, [
          ['Version', 'TLS 1.3 (supported_versions)'], ['server_name (SNI)', '<b>www.example.com</b> ← plaintext'], ['ALPN', 'h2, http/1.1'],
          ['key_share', 'x25519 public key'], ['cipher_suites', 'TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, …']],
          { note: 'The SNI extension repeats the DNS name in cleartext.' }) },
      ],
    });
    S.push({
      title: 'Server proves it owns the name',
      focus: ['web', 'browser'],
      text: '<p>The server replies with ServerHello and key share. Everything after that is encrypted, including its <b>certificate</b>. The browser checks that the certificate\'s <b>subjectAltName</b> matches <code>www.example.com</code> and that it chains to a trusted CA.</p><p>This is what makes DNS spoofing on its own not enough for an attacker: a forged address leads to a server that can\'t present a valid certificate for the name.</p>',
      deep: '<p>Before issuing that certificate, the CA checked the domain\'s <b>CAA</b> records and usually validated control through DNS (an ACME <code>dns-01</code> TXT record) or HTTP. See the Record Types lesson.</p>',
      actions: [
        { send: ['web', 'browser'], tone: 'tls', ms: 20, pkt: N.tls('ServerHello + {Certificate, Finished}', WEB, C.ip4, 443, sp, [
          ['ServerHello', 'TLS 1.3, x25519 key share'], ['{EncryptedExtensions}', 'ALPN = h2'], ['{Certificate}', 'CN/SAN = www.example.com, example.com'],
          ['{CertificateVerify}', 'signature with the site\'s private key'], ['{Finished}', 'handshake MAC']]) },
        { overlay: { id: 'cert', at: 'bl', cls: 'ok', title: 'Certificate check', html: 'SAN <code>www.example.com</code> <span class="good">✓ matches the name looked up in DNS</span><br>Chain → trusted root CA <span class="good">✓</span>' } },
        { send: ['browser', 'web'], tone: 'tls', ms: 0, dur: 700, pkt: N.tls('{Finished}', C.ip4, WEB, sp, 443, [['{Finished}', 'client handshake MAC (encrypted)']]) },
        { link: ['browser', 'web'], id: 'c1', tone: 'tls', label: '🔒 TLS 1.3 · h2' },
      ],
    });
    S.push({
      title: 'HTTP request with the Host / :authority',
      focus: ['browser', 'web'],
      text: '<p>Inside the encrypted tunnel the browser sends <code>GET /</code>. The name appears a third time, as the HTTP/2 <code>:authority</code> pseudo-header (the <code>Host</code> header in HTTP/1.1), which the server uses for virtual hosting.</p>',
      actions: [
        { send: ['browser', 'web'], tone: 'http', ms: 20, pkt: N.appData('GET / (HTTP/2)', C.ip4, WEB, sp, 443, [[':method', 'GET'], [':scheme', 'https'], [':authority', 'www.example.com'], [':path', '/'], ['user-agent', 'Mozilla/5.0 …']]) },
        { send: ['web', 'browser'], tone: 'http', ms: 20, big: true, pkt: N.appData('200 OK text/html', WEB, C.ip4, 443, sp, [[':status', '200'], ['content-type', 'text/html; charset=utf-8'], ['body', '&lt;html&gt; … &lt;img src="https://cdn.example.net/logo.png"&gt; …']]) },
        { overlay: { id: 'html', at: 'bl', title: 'The HTML references another host', html: '<pre>&lt;link rel="stylesheet" href="/site.css"&gt;\n&lt;img src="https://<b style="color:var(--accent)">cdn.example.net</b>/logo.png"&gt;</pre>' + (o.cdn ? '' : '<span class="small muted">(CDN sub-resources are switched off in this scenario)</span>') } },
      ],
    });
    if (o.cdn) {
      S.push({
        title: 'A new hostname means a new DNS lookup',
        focus: ['browser', 'resolver'],
        text: '<p>The page loads resources from <code>cdn.example.net</code>, a different host, so the browser needs another DNS lookup. The answer is a <b>CNAME chain</b>: the CDN\'s DNS returns an address for an edge server <i>near the resolver</i> with a short TTL (60 s), so it can steer traffic around.</p>',
        deep: '<p>CDNs use the resolver\'s IP address, or the EDNS Client Subnet option (RFC 7871), to estimate where you are. Short TTLs let them move you to a different edge quickly when load changes.</p>',
        actions: (() => {
          const q = D.query({ src: C.ip4, dst: R.ip4, name: 'cdn.example.net', type: 'A' });
          const r = D.response(q, { ra: 1, an: [rr('cdn.example.net', 3600, 'CNAME', 'example.edgecdn.example.'), rr('example.edgecdn.example', 60, 'A', CDN)] });
          return [{ send: ['browser', 'resolver'], pkt: q, ms: 8 }, { send: ['resolver', 'browser'], pkt: r, ms: 8 }, { show: ['cdn'] }, { badge: 'cdn', text: 'nearest edge (TTL 60 s)', tone: 'info' }];
        })(),
      });
      S.push({
        title: 'Parallel connection to the CDN edge',
        focus: ['browser', 'cdn'],
        text: '<p>A second TCP + TLS connection opens, this time to the CDN edge, and the image is fetched. The edge is close to you, so its round trips are short. Meanwhile the connection to the origin stays open for other requests.</p>',
        actions: [
          { send: ['browser', 'cdn'], pkt: N.tcp('SYN', C.ip4, CDN, sp2, 443), tone: 'gen', ms: 5 },
          { send: ['cdn', 'browser'], pkt: N.tcp('SYN, ACK', CDN, C.ip4, 443, sp2), tone: 'gen', ms: 5 },
          { send: ['browser', 'cdn'], tone: 'tls', ms: 5, pkt: N.tls('ClientHello', C.ip4, CDN, sp2, 443, [['server_name (SNI)', 'cdn.example.net'], ['ALPN', 'h2']]) },
          { send: ['cdn', 'browser'], tone: 'tls', ms: 5, pkt: N.tls('ServerHello + {Certificate, Finished}', CDN, C.ip4, 443, sp2, [['{Certificate}', 'SAN = cdn.example.net, *.edgecdn.example']]) },
          { link: ['browser', 'cdn'], id: 'c2', tone: 'tls', label: '🔒 TLS · h2' },
          { send: ['browser', 'cdn'], tone: 'http', ms: 5, pkt: N.appData('GET /logo.png', C.ip4, CDN, sp2, 443, [[':method', 'GET'], [':authority', 'cdn.example.net'], [':path', '/logo.png']]) },
          { send: ['cdn', 'browser'], tone: 'http', ms: 5, big: true, pkt: N.appData('200 OK image/png', CDN, C.ip4, 443, sp2, [[':status', '200'], ['content-type', 'image/png'], ['cache-control', 'max-age=31536000']]) },
        ],
      });
    }
    S.push({
      title: 'Page rendered',
      focus: ['browser'],
      text: `<p>A typical page load pulls resources from ${o.cdn ? 'several' : 'one or more'} hosts: fonts, analytics, CDNs, APIs. <b>Each new hostname costs a DNS lookup</b> before its connection can start, unless the answer is already cached.</p><p>That's why sites use <code>&lt;link rel="dns-prefetch"&gt;</code> and <code>&lt;link rel="preconnect"&gt;</code> hints, and why DNS latency matters for web performance.</p>`,
      actions: [{ overlay: { id: 'sum', at: 'bl', cls: 'ok', title: 'This page load', html: `<table><tr><td>DNS lookups</td><td><b>${o.cdn ? 2 : 1}</b></td></tr><tr><td>TCP + TLS connections</td><td><b>${o.cdn ? 2 : 1}</b></td></tr><tr><td>The name was sent in</td><td>DNS query, TLS SNI, HTTP :authority, and checked against the certificate SAN</td></tr></table>` } }],
    });
    return { nodes, links, steps: S, hud: 'lookup', intro: 'After DNS: turning <code>203.0.113.10</code> into a secure web page. Press <b>Play</b>.' };
  }

  /* ------------------------------------------------------------ HTTP/3 via HTTPS RR */
  function h3() {
    const WEB = Wd.web.ip4;
    const sp = 61022;
    const nodes = [
      { id: 'browser', x: 110, y: 290, icon: 'browser', tier: 'client', label: 'Browser', sub: C.ip4 },
      { id: 'resolver', x: 450, y: 90, icon: 'resolver', tier: 'resolver', label: 'Recursive resolver', sub: R.ip4, size: 'sm' },
      { id: 'web', x: 840, y: 300, icon: 'web', tier: 'web', label: 'www.example.com', sub: `${WEB}<br>UDP 443 (QUIC) + TCP 443` },
    ];
    const qa = D.query({ src: C.ip4, dst: R.ip4, name: 'www.example.com', type: 'A' });
    const qh = D.query({ src: C.ip4, dst: R.ip4, name: 'www.example.com', type: 'HTTPS', note: 'HTTPS resource record (type 65, RFC 9460): asks how to connect, not only where.' });
    const ra = D.response(qa, { ra: 1, an: [rr('www.example.com', 300, 'A', WEB)] });
    const rh = D.response(qh, { ra: 1, an: [rr('www.example.com', 300, 'HTTPS', `1 . alpn=h3,h2 ipv4hint=${WEB} ipv6hint=${Wd.web.ip6}`)],
      note: 'ServiceMode record (priority 1). TargetName "." means "this same name". It advertises HTTP/3 (h3) and HTTP/2, plus address hints.' });
    const S = [
      {
        title: 'Ask for A and HTTPS records in parallel',
        focus: ['browser', 'resolver'],
        text: '<p>Modern browsers query the <b>HTTPS</b> record (type 65) alongside A/AAAA. It tells the client <i>how</i> to connect: supported protocols (ALPN), alternative endpoints and ports, and even ECH keys for encrypted SNI.</p>',
        actions: [{ lookup: 'reset' }, { par: [{ send: ['browser', 'resolver'], pkt: qa, ms: 8, bend: 50 }, { send: ['browser', 'resolver'], pkt: qh, ms: 0, bend: 10 }] }],
      },
      {
        title: 'The HTTPS record says: HTTP/3 is available',
        focus: ['resolver', 'browser'],
        text: '<p>The answer <code>1 . alpn=h3,h2 ipv4hint=…</code> tells the browser the server speaks <b>HTTP/3 over QUIC</b>. Without it, the browser would have to open TCP first and only learn about h3 afterwards, from an <code>Alt-Svc</code> response header.</p>',
        deep: '<p>The HTTPS RR also solves the "CNAME at the zone apex" problem: an <b>AliasMode</b> record (priority 0) like <code>example.com. HTTPS 0 cdn.provider.example.</code> can point the bare domain at a CDN.</p>',
        actions: [
          { par: [{ send: ['resolver', 'browser'], pkt: ra, ms: 8, bend: 50 }, { send: ['resolver', 'browser'], pkt: rh, ms: 0, bend: 10 }] },
          { overlay: { id: 'svcb', at: 'tr', title: 'HTTPS RR decoded', html: '<table><tr><th>SvcPriority</th><td>1 (ServiceMode)</td></tr><tr><th>TargetName</th><td>. (same name)</td></tr><tr><th>alpn</th><td><b class="good">h3</b>, h2</td></tr><tr><th>ipv4hint</th><td>203.0.113.10</td></tr><tr><th>ipv6hint</th><td>2001:db8:113::10</td></tr></table>' } },
        ],
      },
      {
        title: 'QUIC Initial: no TCP handshake at all',
        focus: ['browser', 'web'],
        text: '<p>QUIC runs over <b>UDP 443</b> and merges the transport and TLS 1.3 handshakes. The first packet (Initial) already carries the TLS ClientHello, with SNI and ALPN h3.</p>',
        actions: [{ send: ['browser', 'web'], tone: 'tls', ms: 20, pkt: D.generic({ src: C.ip4, dst: WEB, proto: 'QUIC', sport: sp, dport: 443, summary: 'QUIC Initial (CRYPTO: TLS ClientHello)', label: 'QUIC Initial',
          layers: [{ name: 'QUIC IETF — Initial', fields: [['Version', '1 (RFC 9000)'], ['DCID', '8 random bytes'], ['Padding', 'to ≥ 1200 bytes (anti-amplification)'], ['CRYPTO frame', 'TLS 1.3 ClientHello: SNI www.example.com, ALPN h3']] }] }) }],
      },
      {
        title: 'Handshake done in one round trip',
        focus: ['web', 'browser'],
        text: '<p>The server answers with its Initial (ServerHello) and Handshake packets (certificate, Finished). After <b>1 RTT</b> the connection is secure, instead of 2 RTTs for TCP followed by TLS 1.3. On a return visit, <b>0-RTT</b> can even send the request in the very first flight.</p>',
        actions: [
          { send: ['web', 'browser'], tone: 'tls', ms: 20, pkt: D.generic({ src: WEB, dst: C.ip4, proto: 'QUIC', sport: 443, dport: sp, summary: 'QUIC Initial + Handshake (ServerHello, {Certificate}, {Finished})', label: 'QUIC Handshake',
            layers: [{ name: 'QUIC IETF — Initial + Handshake', fields: [['CRYPTO', 'ServerHello, EncryptedExtensions (ALPN h3), Certificate, CertificateVerify, Finished']] }] }) },
          { link: ['browser', 'web'], id: 'q', tone: 'tls', label: '🔒 QUIC · HTTP/3 (UDP 443)' },
        ],
      },
      {
        title: 'HTTP/3 request and response',
        focus: ['browser', 'web'],
        text: '<p>The GET travels on a QUIC stream. Each stream is independent, so a lost packet only delays its own stream, not the whole connection (unlike HTTP/2 over TCP, which suffers head-of-line blocking).</p>',
        actions: [
          { send: ['browser', 'web'], tone: 'http', ms: 20, pkt: N.appData('GET / (HTTP/3)', C.ip4, WEB, sp, 443, [[':method', 'GET'], [':authority', 'www.example.com'], [':path', '/']], { proto: 'QUIC', encName: 'QUIC 1-RTT', outerSummary: 'QUIC 1-RTT protected packet' }) },
          { send: ['web', 'browser'], tone: 'http', ms: 20, big: true, pkt: N.appData('200 OK', WEB, C.ip4, 443, sp, [[':status', '200'], ['content-type', 'text/html']], { proto: 'QUIC', encName: 'QUIC 1-RTT', outerSummary: 'QUIC 1-RTT protected packet' }) },
          { overlay: { id: 'cmp', at: 'bl', title: 'Round trips before the first request', html: '<table><tr><td>TCP + TLS 1.3</td><td><div class="meter" style="width:140px"><i style="width:100%;background:var(--c-gen)"></i></div></td><td>2 RTT</td></tr><tr><td>QUIC (via HTTPS RR)</td><td><div class="meter" style="width:140px"><i style="width:50%;background:var(--c-ok)"></i></div></td><td>1 RTT</td></tr><tr><td>QUIC 0-RTT resume</td><td><div class="meter" style="width:140px"><i style="width:4%;background:var(--c-ok)"></i></div></td><td>0 RTT</td></tr></table>' } },
        ],
      },
    ];
    return { nodes, links: [['browser', 'resolver'], ['browser', 'web']], steps: S, hud: 'lookup', intro: 'The HTTPS record (RFC 9460) lets DNS say <i>how</i> to connect, so the browser can go straight to HTTP/3.' };
  }

  /* ------------------------------------------------------------ email via MX */
  function email(o) {
    const MTA = '198.51.100.25', MX1 = '203.0.113.25', MX2 = '203.0.113.26';
    const nodes = [
      { id: 'alice', x: 90, y: 300, icon: 'mail', tier: 'client', label: "Alice's mail app", sub: 'alice@sender.example' },
      { id: 'mta', x: 330, y: 300, icon: 'mailserver', tier: 'mail', label: 'mail.sender.example', sub: `${MTA} (sending MTA)` },
      { id: 'resolver', x: 590, y: 80, icon: 'resolver', tier: 'resolver', label: 'DNS resolver', sub: 'used by both mail servers', size: 'sm' },
      { id: 'mx1', x: 860, y: 215, icon: 'mailserver', tier: 'mail', label: 'mx1.example.com', sub: `${MX1} · pref 10` },
      { id: 'mx2', x: 860, y: 440, icon: 'mailserver', tier: 'mail', label: 'mx2.example.com', sub: `${MX2} · pref 20` },
    ];
    const links = [['alice', 'mta'], ['mta', 'resolver'], ['mta', 'mx1'], ['mta', 'mx2'], ['mx1', 'resolver'], ['mx2', 'resolver']];
    const target = o.down ? 'mx2' : 'mx1';
    const TIP = o.down ? MX2 : MX1;
    const q = (src, name, type) => D.query({ src, dst: R.ip4, name, type });
    const S = [];
    const qmx = q(MTA, 'example.com', 'MX');
    S.push({
      title: 'Alice presses Send',
      focus: ['alice', 'mta'],
      text: '<p>Alice\'s mail client submits the message to her provider\'s outgoing server over <b>SMTP submission</b> (port 587, with STARTTLS and authentication). The recipient is <code>bob@example.com</code>.</p>',
      actions: [
        { send: ['alice', 'mta'], tone: 'enc', pkt: N.appData('SMTP submission', '192.0.2.10', MTA, 51201, 587, [['AUTH', 'PLAIN (inside TLS)'], ['MAIL FROM', '&lt;alice@sender.example&gt;'], ['RCPT TO', '&lt;bob@example.com&gt;'], ['DATA', 'Subject: Lunch?']], { outerSummary: 'SMTP submission over TLS (587)' }) },
        { badge: 'mta', text: 'rcpt domain: example.com', tone: 'info' },
      ],
    });
    S.push({
      title: 'Where does example.com receive mail? → MX lookup',
      focus: ['mta', 'resolver'],
      text: '<p>The sending server takes the domain after the <code>@</code> and asks for its <b>MX</b> (Mail eXchanger) records. MX records point to <i>hostnames</i>, never directly to IP addresses.</p>',
      actions: [{ send: ['mta', 'resolver'], pkt: qmx }],
    });
    S.push({
      title: 'MX answer: preference decides the order',
      focus: ['resolver', 'mta'],
      text: '<p>Two MX records come back. The <b>lower preference number wins</b>: try <code>mx1</code> (10) first and fall back to <code>mx2</code> (20). Equal preferences would be picked at random, which spreads the load.</p>',
      deep: '<p>If a domain has no MX record, RFC 5321 falls back to its A/AAAA record (the "implicit MX"). A "null MX" (<code>MX 0 .</code>, RFC 7505) says the domain accepts no mail at all.</p>',
      actions: [
        { send: ['resolver', 'mta'], pkt: D.response(qmx, { ra: 1, an: [rr('example.com', 3600, 'MX', '10 mx1.example.com.'), rr('example.com', 3600, 'MX', '20 mx2.example.com.')] }) },
        { overlay: { id: 'mx', at: 'bl', title: 'Sorted by preference', html: '<table><tr><th>Pref</th><th>Host</th></tr><tr><td class="good"><b>10</b></td><td>mx1.example.com ← try first</td></tr><tr><td>20</td><td>mx2.example.com (backup)</td></tr></table>' } },
      ],
    });
    const qa1 = q(MTA, 'mx1.example.com', 'A');
    S.push({
      title: 'Resolve the mail server\'s address',
      focus: ['mta', 'resolver'],
      text: '<p>The MX target is a hostname, so it needs its own A/AAAA lookup. (Resolvers often include these addresses in the Additional section, which saves a round trip.)</p>',
      actions: [{ send: ['mta', 'resolver'], pkt: qa1 }, { send: ['resolver', 'mta'], pkt: D.response(qa1, { ra: 1, an: [rr('mx1.example.com', 3600, 'A', MX1)] }) }],
    });
    if (o.down) {
      const qa2 = q(MTA, 'mx2.example.com', 'A');
      S.push({
        title: 'mx1 is down: connection times out',
        focus: ['mta', 'mx1'],
        text: '<p>The SYN to <code>mx1</code> gets no reply. After a timeout, SMTP moves on to the <b>next MX by preference</b>. This is DNS-driven failover, built into mail routing since the 1980s.</p>',
        actions: [
          { cls: ['mx1', 'down'] },
          { send: ['mta', 'mx1'], pkt: N.tcp('SYN', MTA, MX1, 40311, 25), tone: 'gen' },
          { badge: 'mx1', text: 'no response (timeout)', tone: 'bad' },
          { send: ['mta', 'resolver'], pkt: qa2 },
          { send: ['resolver', 'mta'], pkt: D.response(qa2, { ra: 1, an: [rr('mx2.example.com', 3600, 'A', MX2)] }) },
        ],
      });
    }
    S.push({
      title: `SMTP to ${target}.example.com, port 25`,
      focus: ['mta', target],
      text: '<p>TCP handshake to port 25. The receiving server greets with a <code>220</code> banner, the client says <code>EHLO</code>, and they upgrade to TLS with <code>STARTTLS</code>.</p>',
      deep: '<p>STARTTLS between mail servers is opportunistic, so an attacker could strip it. <b>MTA-STS</b> (a TXT record plus an HTTPS policy) and <b>DANE</b> (TLSA records protected by DNSSEC) let a domain require TLS.</p>',
      actions: [
        { send: ['mta', target], pkt: N.tcp('SYN', MTA, TIP, 40312, 25), tone: 'gen' },
        { send: [target, 'mta'], pkt: N.tcp('SYN, ACK', TIP, MTA, 25, 40312), tone: 'gen' },
        { send: [target, 'mta'], tone: 'smtp', pkt: N.smtp(`220 ${target}.example.com ESMTP`, TIP, MTA, 25, 40312) },
        { send: ['mta', target], tone: 'smtp', pkt: N.smtp('EHLO mail.sender.example', MTA, TIP, 40312, 25) },
        { link: ['mta', target], id: 'smtp', tone: 'tls', label: '🔒 SMTP + STARTTLS' },
      ],
    });
    S.push({
      title: 'MAIL FROM, RCPT TO, DATA',
      focus: ['mta', target],
      text: '<p>The <b>envelope</b> (MAIL FROM / RCPT TO) is separate from the headers the user sees. Before accepting the message, the receiver will use DNS to check whether the sender is who it claims to be.</p>',
      actions: [
        { send: ['mta', target], tone: 'smtp', pkt: N.appData('MAIL FROM:<alice@sender.example>', MTA, TIP, 40312, 25, [['MAIL FROM', '&lt;alice@sender.example&gt;'], ['RCPT TO', '&lt;bob@example.com&gt;']]) },
        { send: ['mta', target], tone: 'smtp', big: true, pkt: N.appData('DATA (DKIM-signed message)', MTA, TIP, 40312, 25, [['DKIM-Signature', 'v=1; a=ed25519-sha256; d=sender.example; s=sel1; bh=…; b=…'], ['From', 'Alice &lt;alice@sender.example&gt;'], ['Subject', 'Lunch?']]) },
      ],
    });
    const qptr = q(TIP, '25.100.51.198.in-addr.arpa', 'PTR');
    const qspf = q(TIP, 'sender.example', 'TXT');
    const qdkim = q(TIP, 'sel1._domainkey.sender.example', 'TXT');
    const qdmarc = q(TIP, '_dmarc.sender.example', 'TXT');
    S.push({
      title: 'Receiver checks reverse DNS (PTR)',
      focus: [target, 'resolver'],
      text: `<p>The receiving server looks up the <b>PTR</b> record of the connecting IP <code>${MTA}</code> (written backwards under <code>in-addr.arpa</code>), then checks that the returned name resolves back to the same IP. This is called <b>forward-confirmed reverse DNS</b>. Many receivers penalise senders without it.</p>`,
      actions: [
        { send: [target, 'resolver'], pkt: qptr },
        { send: ['resolver', target], pkt: D.response(qptr, { ra: 1, an: [rr('25.100.51.198.in-addr.arpa', 3600, 'PTR', 'mail.sender.example.')] }) },
        { badge: target, text: 'FCrDNS ✓', tone: 'ok' },
      ],
    });
    S.push({
      title: 'SPF, DKIM and DMARC: all TXT records',
      focus: [target, 'resolver'],
      text: '<p>Three more DNS lookups authenticate the sender:</p><ul><li><b>SPF</b> (<code>sender.example TXT</code>): which IPs may send for this domain? <span class="good">198.51.100.25 is listed → pass</span></li><li><b>DKIM</b> (<code>sel1._domainkey TXT</code>): the public key that verifies the message signature. <span class="good">Signature valid</span></li><li><b>DMARC</b> (<code>_dmarc TXT</code>): the domain\'s policy if checks fail (p=reject), and where to send reports.</li></ul>',
      actions: [
        { send: [target, 'resolver'], pkt: qspf },
        { send: ['resolver', target], pkt: D.response(qspf, { ra: 1, an: [rr('sender.example', 3600, 'TXT', '"v=spf1 ip4:198.51.100.25 -all"')] }) },
        { send: [target, 'resolver'], pkt: qdkim },
        { send: ['resolver', target], pkt: D.response(qdkim, { ra: 1, an: [rr('sel1._domainkey.sender.example', 3600, 'TXT', '"v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="')] }) },
        { send: [target, 'resolver'], pkt: qdmarc },
        { send: ['resolver', target], pkt: D.response(qdmarc, { ra: 1, an: [rr('_dmarc.sender.example', 3600, 'TXT', '"v=DMARC1; p=reject; rua=mailto:dmarc@sender.example"')] }) },
        { overlay: { id: 'auth', at: 'bl', cls: 'ok', title: 'Sender authentication', html: '<table><tr><td>SPF</td><td class="good">pass</td></tr><tr><td>DKIM (d=sender.example)</td><td class="good">pass</td></tr><tr><td>DMARC alignment</td><td class="good">pass</td></tr></table>' } },
      ],
    });
    S.push({
      title: '250 OK: queued for Bob',
      focus: [target, 'mta'],
      text: `<p>The receiver accepts the message (<code>250 2.0.0 OK</code>) and delivers it to Bob's mailbox. One email took <b>${o.down ? 7 : 6} DNS lookups</b>: MX, A${o.down ? ' ×2' : ''}, PTR, and TXT ×3.</p>`,
      actions: [{ send: [target, 'mta'], tone: 'smtp', pkt: N.appData('250 2.0.0 OK queued', TIP, MTA, 25, 40312, [['Reply', '250 2.0.0 OK: queued as 4F2A1C']]) }, { badge: target, text: '📬 delivered to bob', tone: 'ok' }],
    });
    return { nodes, links, steps: S, intro: `Delivering <code>alice@sender.example → bob@example.com</code>${o.down ? ' while the primary MX is down' : ''}. Watch how many DNS lookups one email needs.` };
  }

  /* ------------------------------------------------------------ SRV */
  function srv() {
    const S1 = '203.0.113.61', S2 = '203.0.113.62';
    const nodes = [
      { id: 'phone', x: 110, y: 290, icon: 'voip', tier: 'client', label: 'Softphone app', sub: 'bob@example.com' },
      { id: 'resolver', x: 450, y: 90, icon: 'resolver', tier: 'resolver', label: 'Recursive resolver', sub: R.ip4, size: 'sm' },
      { id: 'sip1', x: 840, y: 180, icon: 'server', tier: 'web', label: 'sip1.example.com', sub: `${S1}:5061 · prio 10 wt 60` },
      { id: 'sip2', x: 840, y: 420, icon: 'server', tier: 'web', label: 'sip2.example.com', sub: `${S2}:5061 · prio 10 wt 40` },
    ];
    const q = D.query({ src: C.ip4, dst: R.ip4, name: '_sips._tcp.example.com', type: 'SRV', note: 'Service name is _service._proto.domain: SIP over TLS (sips) on TCP.' });
    const r = D.response(q, { ra: 1,
      an: [rr('_sips._tcp.example.com', 3600, 'SRV', '10 60 5061 sip1.example.com.'), rr('_sips._tcp.example.com', 3600, 'SRV', '10 40 5061 sip2.example.com.'), rr('_sips._tcp.example.com', 3600, 'SRV', '20 0 5061 sip-backup.example.com.')],
      ar: [rr('sip1.example.com', 3600, 'A', S1), rr('sip2.example.com', 3600, 'A', S2)],
      note: 'Additional-section addresses let the client skip separate A lookups.' });
    const sp = 52311;
    const S = [
      {
        title: 'The app only knows a domain',
        focus: ['phone'],
        text: '<p>Bob typed <code>bob@example.com</code> into his VoIP app. Which server, which port, which transport? Instead of hard-coding these, the app asks DNS for an <b>SRV</b> record (RFC 2782) named <code>_service._proto.domain</code>.</p>',
        actions: [{ badge: 'phone', text: 'needs: host + port for SIP/TLS', tone: 'info' }],
      },
      {
        title: 'Query _sips._tcp.example.com SRV',
        focus: ['phone', 'resolver'],
        text: '<p>The underscore labels can\'t clash with real hostnames. <code>_sips</code> is the service and <code>_tcp</code> is the transport.</p>',
        deep: '<p>Full SIP resolution (RFC 3263) can start with NAPTR records to pick the transport before the SRV lookup. Many clients skip straight to SRV.</p>',
        actions: [{ send: ['phone', 'resolver'], pkt: q }],
      },
      {
        title: 'SRV answer: priority, weight, port, target',
        focus: ['resolver', 'phone'],
        text: '<p>Each SRV record carries <b>priority</b> (lower tried first), <b>weight</b> (load share among equal priorities), <b>port</b> and <b>target</b> host. <code>sip1</code> and <code>sip2</code> share priority 10 with weights 60/40. <code>sip-backup</code> (priority 20) is used only if both fail.</p>',
        actions: [
          { send: ['resolver', 'phone'], pkt: r },
          { overlay: { id: 'srv', at: 'bl', title: 'Weighted random choice among priority 10', html: '<div class="small">sip1 · weight 60</div><div class="meter" style="width:220px"><i style="width:60%"></i></div><div class="small">sip2 · weight 40</div><div class="meter" style="width:220px"><i style="width:40%;background:var(--t-resolver)"></i></div><div>🎲 rolled 23 of 100 → <b class="good">sip1.example.com:5061</b></div>' } },
        ],
      },
      {
        title: 'Connect to the port from DNS',
        focus: ['phone', 'sip1'],
        text: '<p>The app connects to <code>203.0.113.61</code> on port <b>5061</b>. Both the address <i>and the port</i> came from DNS, so the operator can move the service or change ports without reconfiguring any clients.</p>',
        actions: [
          { send: ['phone', 'sip1'], pkt: N.tcp('SYN', C.ip4, S1, sp, 5061), tone: 'gen' },
          { send: ['sip1', 'phone'], pkt: N.tcp('SYN, ACK', S1, C.ip4, 5061, sp), tone: 'gen' },
          { send: ['phone', 'sip1'], tone: 'tls', pkt: N.tls('ClientHello', C.ip4, S1, sp, 5061, [['server_name (SNI)', 'sip1.example.com']]) },
          { link: ['phone', 'sip1'], id: 's', tone: 'tls', label: '🔒 SIP over TLS :5061' },
        ],
      },
      {
        title: 'SIP REGISTER → 200 OK',
        focus: ['phone', 'sip1'],
        text: '<p>The softphone registers, and incoming calls for bob@example.com can now reach it.</p>',
        actions: [
          { send: ['phone', 'sip1'], tone: 'http', pkt: N.appData('REGISTER sips:example.com', C.ip4, S1, sp, 5061, [['Request-Line', 'REGISTER sips:example.com SIP/2.0'], ['From', '&lt;sips:bob@example.com&gt;'], ['Contact', '&lt;sips:bob@192.0.2.10:52311;transport=tls&gt;']]) },
          { send: ['sip1', 'phone'], tone: 'http', pkt: N.appData('SIP/2.0 200 OK', S1, C.ip4, 5061, sp, [['Status-Line', 'SIP/2.0 200 OK'], ['Expires', '3600']]) },
          { badge: 'phone', text: 'registered ✓', tone: 'ok' },
        ],
      },
      {
        title: 'SRV is everywhere',
        focus: ['phone', 'sip2'],
        text: '<p>If sip1 stops answering, the client moves to sip2 (same priority), then to sip-backup. SRV is used well beyond VoIP:</p><ul><li><code>_ldap._tcp.dc._msdcs.corp.example</code>: Active Directory domain controllers</li><li><code>_kerberos._udp</code>: Kerberos KDCs</li><li><code>_xmpp-client._tcp</code>: chat servers</li><li><code>_minecraft._tcp</code>: game servers on custom ports</li><li><code>_imaps._tcp</code> and <code>_submission._tcp</code>: mail client auto-configuration (RFC 6186)</li></ul>',
        actions: [{ overlay: { id: 'fo', at: 'bl', title: 'Failover order', html: '<div class="chips"><span class="chip ok">sip1 (10/60)</span><span class="chip">sip2 (10/40)</span><span class="chip dim">sip-backup (20)</span></div>' } }],
      },
    ];
    return { nodes, links: [['phone', 'resolver'], ['phone', 'sip1'], ['phone', 'sip2']], steps: S, intro: 'An app finds its server <i>and port</i> through an SRV record.' };
  }

  DV.register({
    id: 'connect',
    nav: 'Using the answer',
    title: 'Using the answer: web, mail and apps',
    icon: 'connect',
    blurb: 'What happens after DNS: the TCP/TLS/HTTP page load with CDN sub-resources, HTTP/3 via HTTPS records, email routing with MX/SPF/DKIM, and SRV-based service discovery.',
    intro: '<p>DNS is only the first step. Here you can see how different applications <b>use</b> the answer: a browser opening TLS connections, a mail server following MX records and checking SPF/DKIM/DMARC, and a VoIP app finding host and port through SRV.</p>',
    options: [
      { id: 'app', type: 'segmented', label: 'Application', value: 'web', choices: [['web', 'Web page'], ['h3', 'HTTP/3 via HTTPS RR'], ['email', 'Email (MX)'], ['srv', 'VoIP (SRV)']] },
      { id: 'cdn', type: 'check', label: 'Load a CDN sub-resource', value: true, visibleIf: (o) => o.app === 'web' },
      { id: 'down', type: 'check', label: 'Primary MX is down', value: false, visibleIf: (o) => o.app === 'email' },
    ],
    build(o) {
      if (o.app === 'h3') return h3(o);
      if (o.app === 'email') return email(o);
      if (o.app === 'srv') return srv(o);
      return web(o);
    },
  });
})();
