/* Section 1 — Full recursive resolution: browser → stub → resolver → root → TLD → authoritative. */
(function () {
  'use strict';
  const DV = window.DV;
  const D = DV.dns;
  const Wd = DV.world;
  const rr = D.rr;

  const GTLD = { name: 'a.gtld-servers.net.', ip4: '192.5.6.30', ip6: '2001:503:a83e::2:30', others: ['b.gtld-servers.net.', 'c.gtld-servers.net.'] };
  const DOMAIN_RE = /^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$/;

  function tldServer(tld, h) {
    if (tld === 'com' || tld === 'net') return GTLD;
    return {
      name: `a.nic.${tld}.`, ip4: `192.0.2.${100 + (h % 100)}`, ip6: `2001:db8:ffff::${(h % 4000).toString(16)}`,
      others: [`b.nic.${tld}.`], illustrative: true,
    };
  }

  function ipc(summary, label, fields, note) {
    return D.generic({ kind: 'ipc', local: true, summary, label, note, layers: [{ name: 'Local API call (no network packet)', fields }] });
  }

  DV.register({
    id: 'resolution',
    nav: 'Full resolution',
    title: 'Full recursive resolution',
    icon: 'flow',
    blurb: 'Follow a single lookup from the browser, through the stub resolver and recursive resolver, down the root → TLD → authoritative hierarchy, and back again.',
    intro: `<p>What happens between typing <code>www.example.com</code> and your browser having an IP address? Several caches are checked, then a <b>recursive resolver</b> walks the DNS hierarchy on your behalf with <b>iterative</b> queries. It follows <b>referrals</b> from the root to the TLD to the zone's <b>authoritative</b> servers.</p>`,
    options: [
      { id: 'domain', type: 'text', label: 'Domain', value: 'www.example.com', placeholder: 'www.example.com',
        validate: (v) => (DOMAIN_RE.test(v) ? null : 'Enter a valid hostname, e.g. www.example.org') },
      { id: 'qtype', type: 'segmented', label: 'Query type', value: 'A', choices: [['A', 'A (IPv4)'], ['AAAA', 'AAAA (IPv6)']] },
      { id: 'cache', type: 'select', label: 'Cache state', value: 'cold', choices: [
        ['cold', 'Cold: nothing cached'], ['tld', 'Resolver knows .TLD servers'], ['hit', 'Resolver has the answer'], ['browser', 'Browser cache hit']] },
      { id: 'qmin', type: 'check', label: 'QNAME minimisation', value: false, help: 'RFC 9156: send each server only the part of the name it needs to see' },
      { id: 'tc', type: 'check', label: 'Truncated answer → TCP', value: false, help: 'The authoritative answer comes back with TC=1 and the resolver retries over TCP' },
    ],

    build(o) {
      const name = D.fqdn(o.domain);
      const host = D.bare(name);
      const labels = host.split('.');
      const tld = labels[labels.length - 1];
      const zone = labels.slice(-2).join('.') + '.';
      const h = D.hashStr(host);
      const T = tldServer(tld, h);
      const isExample = zone === 'example.com.';
      const authName = 'ns1.' + zone;
      const authIp4 = isExample ? Wd.auth.ip4 : `203.0.113.${40 + (h % 20)}`;
      const authIp6 = isExample ? Wd.auth.ip6 : `2001:db8:113::${(40 + (h % 20)).toString(16)}`;
      const v4 = host === 'www.example.com' ? Wd.web.ip4 : `203.0.113.${100 + (h % 150)}`;
      const v6 = host === 'www.example.com' ? Wd.web.ip6 : `2001:db8:113::${(h % 65000).toString(16)}`;
      const qt = o.qtype;
      const data = qt === 'A' ? v4 : v6;
      const C = Wd.client, R = Wd.resolver, RT = Wd.root;
      const TTL = 3600;

      const nodes = [
        { id: 'browser', x: 95, y: 130, icon: 'browser', tier: 'client', label: 'Web browser', sub: 'has its own DNS cache', cacheAt: 'below-left' },
        { id: 'stub', x: 95, y: 420, icon: 'stub', tier: 'client', label: 'OS stub resolver', sub: C.ip4, cacheAt: 'above-left' },
        { id: 'resolver', x: 470, y: 300, icon: 'resolver', tier: 'resolver', label: 'Recursive resolver', sub: `${R.name}<br>${R.ip4}`, cacheAt: 'below' },
        { id: 'root', x: 855, y: 118, icon: 'root', tier: 'root', label: 'Root server', sub: `a.root-servers.net<br>${RT.ip4}` },
        { id: 'tld', x: 855, y: 290, icon: 'tld', tier: 'tld', label: `.${tld} TLD server`, sub: `${D.bare(T.name)}<br>${T.ip4}` },
        { id: 'auth', x: 855, y: 452, icon: 'auth', tier: 'auth', label: `Authoritative for ${D.bare(zone)}`, sub: `${D.bare(authName)}<br>${authIp4}` },
        { id: 'web', x: 700, y: 185, icon: 'web', tier: 'web', label: host, sub: qt === 'A' ? v4 : v6, hidden: true, size: 'sm' },
      ];
      const links = [['browser', 'stub'], ['stub', 'resolver'], ['resolver', 'root'], ['resolver', 'tld'], ['resolver', 'auth'], ['browser', 'web']];
      const groups = [
        { x: 15, y: 16, w: 160, h: 532, label: 'Your computer' },
        { x: 735, y: 16, w: 250, h: 532, label: 'DNS hierarchy' },
      ];

      /* ---- packets ---- */
      const q1 = D.query({ src: C.ip4, dst: R.ip4, name, type: qt, rd: 1,
        note: 'Recursive query: RD=1 asks the resolver to do the whole job. The random source port and 16-bit ID help protect against spoofed replies.' });
      const rootQName = o.qmin ? tld + '.' : name;
      const rootQType = o.qmin ? 'NS' : qt;
      const qRoot = D.query({ src: R.ip4, dst: RT.ip4, name: rootQName, type: rootQType, rd: 0,
        note: o.qmin ? 'QNAME minimisation: the root only needs to know which TLD you want, so it is not told the full name.' : 'Iterative query (RD=0). The full name is sent, so the root server sees exactly which host you are looking up.' });
      const tldNS = [T.name, ...T.others];
      const rRoot = D.response(qRoot, {
        ns: tldNS.map((n) => rr(tld + '.', 172800, 'NS', n)),
        ar: [rr(T.name, 172800, 'A', T.ip4), rr(T.name, 172800, 'AAAA', T.ip6)],
        note: `Referral: AA=0 and the answer section is empty. The authority section names the .${tld} servers, and the additional section carries their <b>glue</b> addresses. (Trimmed for clarity: the real referral lists all ${tld === 'com' ? '13 ' : ''}TLD servers.)`,
      });
      const tldQName = o.qmin && labels.length > 2 ? zone : name;
      const tldQType = o.qmin && labels.length > 2 ? 'NS' : qt;
      const qTld = D.query({ src: R.ip4, dst: T.ip4, name: tldQName, type: tldQType, rd: 0 });
      const rTld = D.response(qTld, {
        ns: [rr(zone, 172800, 'NS', authName), rr(zone, 172800, 'NS', 'ns2.' + zone)],
        ar: [rr(authName, 172800, 'A', authIp4), rr(authName, 172800, 'AAAA', authIp6)],
        note: `Referral to the zone's name servers. <b>${D.bare(authName)}</b> is inside <b>${D.bare(zone)}</b>, so the TLD must include glue records; otherwise the resolver could never find the server's address.`,
      });
      const qAuth = D.query({ src: R.ip4, dst: authIp4, name, type: qt, rd: 0 });
      const ans = [rr(name, TTL, qt, data)];
      const rAuth = D.response(qAuth, { aa: 1, an: ans, note: 'Authoritative answer: AA=1. The TTL (3600 s) tells every cache how long it may keep this record.' });
      const rAuthTC = D.response(qAuth, { aa: 1, tc: 1, note: 'TC=1: the answer did not fit in the advertised UDP size, so the resolver must retry over TCP.' });
      const qAuthTcp = D.query({ src: R.ip4, dst: authIp4, name, type: qt, rd: 0, tcp: true, dport: 53, note: 'Same question over TCP. Each DNS message is preceded by a 2-byte length field.' });
      const rAuthTcp = D.response(qAuthTcp, { aa: 1, an: ans });
      const hit = o.cache === 'hit';
      const age = 1183;
      const rStub = D.response(q1, { ra: 1, an: [rr(name, hit ? TTL - age : TTL, qt, data)],
        note: hit ? `Answered from cache. The TTL has been counted down to ${TTL - age} s (it was stored ${age} s ago).` : 'RA=1: recursion available. AA=0: the resolver is not authoritative; it is passing on an answer it found. The ID matches the stub\'s query.' });
      const tcp = (flags, src, dst, sp, dp, v) => D.generic({ src, dst, v: v || 4, proto: 'TCP', sport: sp, dport: dp, tcpFlags: flags, summary: `TCP ${flags} ${sp} → ${dp}`, label: flags });

      /* ---- setup: caches ---- */
      const setup = [
        { cache: 'resolver', title: 'Resolver cache', add: [{ name: '.', type: 'NS', data: 'a.root-servers.net.', ttl: 518400, age: 3600 }] },
      ];
      if (o.cache === 'tld' || hit) {
        setup.push({ cache: 'resolver', add: [
          { name: tld + '.', type: 'NS', data: T.name, ttl: 172800, age: 51000 },
          { name: T.name, type: 'A', data: T.ip4, ttl: 172800, age: 51000 },
        ] });
      }
      if (hit) setup.push({ cache: 'resolver', add: [{ name: zone, type: 'NS', data: authName, ttl: 172800, age: 1183 }, { name, type: qt, data, ttl: TTL, age }] });
      if (o.cache === 'browser') setup.push({ cache: 'browser', title: 'Browser cache', add: [{ name, type: qt, data, ttl: 60, age: 22 }] });
      else setup.push({ cache: 'browser', title: 'Browser cache', add: [] });

      /* ---- steps ---- */
      const S = [];
      S.push({
        title: 'You type a URL',
        focus: ['browser'],
        text: `<p>The browser parses <code>https://${host}/</code> and pulls out the <b>hostname</b>. TCP/IP routes packets to <i>addresses</i>, not names, so before any connection can start the name has to be resolved.</p><p>The cheapest place to look first is the browser's own in-memory DNS cache.</p>`,
        deep: '<p>Chrome shows its host cache at <code>chrome://net-internals/#dns</code>. Browsers may also speculatively resolve hostnames found in links (<code>dns-prefetch</code>) before you click them.</p>',
        actions: [
          { overlay: { id: 'url', at: 'top', title: 'URL anatomy', html: `<div class="chips"><span class="chip dim">https://</span><span class="chip hot">${host}</span><span class="chip dim">/index.html</span></div><div class="small muted">scheme · <b style="color:var(--accent)">hostname → needs DNS</b> · path</div>` } },
          { wait: 900 },
          o.cache === 'browser'
            ? { badge: 'browser', text: 'Browser cache: HIT ✓', tone: 'ok' }
            : { badge: 'browser', text: 'Browser cache: MISS', tone: 'bad' },
        ],
      });

      if (o.cache === 'browser') {
        S.push({
          title: 'Answered from the browser cache',
          focus: ['browser'],
          text: `<p>A recent lookup left <code>${host} ${qt} ${data}</code> in the browser's cache, and its TTL hasn't expired yet. <b>No packets are sent at all</b>: the lookup takes microseconds.</p><p>This is why the second visit to a site feels faster. Try the <i>Cold</i> cache state to see everything that is being skipped.</p>`,
          actions: [{ badge: 'browser', text: `${qt} ${data} (0 ms)`, tone: 'ok' }],
        });
      } else {
        S.push({
          title: 'Ask the operating system',
          focus: ['browser', 'stub'],
          text: `<p>The browser calls the OS resolver API (<code>getaddrinfo()</code> on Linux and macOS, <code>GetAddrInfoExW</code> on Windows). The <b>stub resolver</b> checks the <code>hosts</code> file first, then the OS-wide DNS cache (systemd-resolved, mDNSResponder or the Windows DNS Client service).</p>`,
          deep: `<p>The order of these sources is configurable (<code>/etc/nsswitch.conf</code>: <code>hosts: files dns</code>). A real dual-stack host usually sends <b>both A and AAAA</b> queries in parallel. Here we follow the ${qt} query; the IPv4 vs IPv6 lesson shows both.</p>`,
          actions: [
            { send: ['browser', 'stub'], tone: 'ipc', bend: 0, pkt: ipc(`getaddrinfo("${host}", "https")`, 'getaddrinfo()', [
              ['Function', 'getaddrinfo()'], ['node', host], ['service', 'https → port 443'], ['hints.ai_family', 'AF_UNSPEC (IPv4 or IPv6)'], ['Configured DNS server', `${R.ip4} (learned via DHCP / IPv6 RA)`]]) },
            { badge: 'stub', text: '/etc/hosts: no entry', tone: 'info' },
            { wait: 900 },
            { badge: 'stub', text: 'OS cache: MISS', tone: 'bad' },
          ],
        });

        S.push({
          title: 'Stub → recursive resolver (RD=1)',
          focus: ['stub', 'resolver'],
          text: `<p>The stub builds a DNS query and sends it over <b>UDP to port 53</b> of the configured recursive resolver. It sets <b>RD=1</b> (Recursion Desired): <i>"please find the final answer for me."</i></p><p>Click the packet to see the 12-byte header, the question section and the EDNS(0) OPT record.</p>`,
          deep: '<p>The stub picks a random 16-bit <b>transaction ID</b> and a random ephemeral <b>source port</b>. A reply is accepted only if both match, which makes blind spoofing much harder (see the Attacks lesson). EDNS(0) (RFC 6891) advertises a 1232-byte UDP buffer, the value agreed on for DNS Flag Day 2020 so that responses avoid IP fragmentation.</p>',
          actions: [{ lookup: 'reset' }, { send: ['stub', 'resolver'], pkt: q1, ms: 6 }],
        });

        if (hit) {
          S.push({
            title: 'Resolver cache: HIT',
            focus: ['resolver'],
            text: `<p>Someone else using this resolver looked up <code>${host}</code> ${age} seconds ago, and the record is still within its ${TTL}-second TTL. The resolver can answer <b>straight from its cache</b>, with no root, TLD or authoritative queries.</p><p>This sharing is why a large ISP's resolvers answer most queries from cache.</p>`,
            actions: [{ badge: 'resolver', text: 'cache HIT ✓', tone: 'ok' }],
          });
        } else {
          S.push({
            title: o.cache === 'tld' ? `Resolver cache: knows the .${tld} servers` : 'Resolver cache: MISS',
            focus: ['resolver'],
            text: o.cache === 'tld'
              ? `<p>No answer for <code>${host}</code> is cached, but the resolver still has the <code>${tld}.</code> NS records (TTL 2 days) from an earlier lookup. It can <b>skip the root</b> and go straight to the .${tld} servers. In practice most root traffic is avoided this way.</p>`
              : '<p>Nothing useful is cached, so the resolver has to start at the top of the tree. At startup it loaded the <b>root hints</b> (the names and addresses of the 13 root server identities) and refreshed them with a <i>priming query</i>.</p>',
            deep: '<p>Resolvers cache every NS and glue record they learn, so a cold walk from the root is rare. The root hints file is <code>named.root</code> from IANA. RFC 8806 even lets a resolver keep a local copy of the whole root zone.</p>',
            actions: [{ badge: 'resolver', text: o.cache === 'tld' ? `cached: ${tld}. NS` : 'cache MISS', tone: o.cache === 'tld' ? 'info' : 'bad' }],
          });

          if (o.cache === 'cold') {
            S.push({
              title: 'Resolver → root server',
              focus: ['resolver', 'root'],
              text: o.qmin
                ? `<p>With <b>QNAME minimisation</b> the resolver asks the root only <code>${tld}. NS?</code>. The root doesn't need to know you want <code>${host}</code>; it only needs to say who runs <code>.${tld}</code>.</p>`
                : `<p>The resolver sends an <b>iterative</b> query (RD=0) for the full name to <code>a.root-servers.net</code>. The root servers don't know the answer, but they know who to ask next.</p>`,
              deep: '<p>There are 13 root server <i>identities</i> (a–m), run by 12 organisations, but more than 1,900 physical instances announce the same addresses by <b>anycast</b>. BGP routing sends your packet to a nearby instance, which is why this hop takes only a few milliseconds.</p>',
              actions: [
                { send: ['resolver', 'root'], pkt: qRoot, ms: 10 },
                o.qmin ? { overlay: { id: 'qm', at: 'tr', title: 'What the root server sees', html: `<code>${tld}. NS?</code> <span class="good">only the TLD</span>` } } : { badge: 'root', text: `sees: ${host}`, tone: 'warn' },
              ],
            });
            S.push({
              title: `Root replies with a referral to .${tld}`,
              focus: ['root', 'resolver'],
              text: `<p>The root is not authoritative for <code>${host}</code>, so it returns a <b>referral</b>: AA=0 and an empty answer section. The <b>authority</b> section lists the <code>${tld}.</code> NS records, and the <b>additional</b> section gives their IP addresses as <b>glue</b>.</p><p>The resolver caches all of it. Those records have a 2-day TTL.</p>`,
              deep: `<p>Referral TTLs are long (172800 s) because delegations rarely change. This is why the root handles far less traffic than you might expect.${T.illustrative ? ` (Server names and addresses for .${tld} are illustrative.)` : ''}</p>`,
              actions: [
                { send: ['root', 'resolver'], pkt: rRoot, ms: 10 },
                { badge: 'root', text: 'referral (AA=0)', tone: 'warn' },
                { cache: 'resolver', add: [{ name: tld + '.', type: 'NS', data: T.name, ttl: 172800 }, { name: T.name, type: 'A', data: T.ip4, ttl: 172800 }] },
              ],
            });
          }

          S.push({
            title: `Resolver → .${tld} TLD server`,
            focus: ['resolver', 'tld'],
            text: o.qmin && labels.length > 2
              ? `<p>The resolver now asks the .${tld} server <code>${D.bare(zone)}. NS?</code>. This is still minimised: the TLD learns the registered domain but not the <code>${labels[0]}</code> host label.</p>`
              : `<p>The resolver repeats the question to one of the .${tld} servers it just learned about. The TLD registry's servers hold one delegation (NS records plus glue) for every registered domain.</p>`,
            deep: '<p>Resolvers pick among the listed servers by measured round-trip time (<i>smoothed RTT</i>) and fall back to another server if one doesn\'t respond. The .com zone holds more than 150 million delegations.</p>',
            actions: [{ send: ['resolver', 'tld'], pkt: qTld, ms: 14 }],
          });
          S.push({
            title: `TLD refers to ${D.bare(zone)}'s name servers`,
            focus: ['tld', 'resolver'],
            text: `<p>Another referral: <code>${D.bare(zone)}. NS ${D.bare(authName)}.</code>. The name server lives <i>inside</i> the zone it serves, so the TLD also sends its address as <b>glue</b>. Without glue the resolver would be stuck in a loop: to find ns1.${D.bare(zone)} it would first have to ask ns1.${D.bare(zone)}.</p>`,
            deep: '<p>The NS set at the parent (the delegation) and the NS set at the child (the authoritative copy) should match. When a listed server doesn\'t actually answer for the zone, that is called a <i>lame delegation</i>.</p>',
            actions: [
              { send: ['tld', 'resolver'], pkt: rTld, ms: 14 },
              { badge: 'tld', text: 'referral + glue', tone: 'warn' },
              { cache: 'resolver', add: [{ name: zone, type: 'NS', data: authName, ttl: 172800 }, { name: authName, type: 'A', data: authIp4, ttl: 172800 }] },
            ],
          });
          S.push({
            title: 'Resolver → authoritative server',
            focus: ['resolver', 'auth'],
            text: `<p>Finally the resolver asks a server that actually holds the <code>${D.bare(zone)}</code> zone: <code>${host} ${qt}?</code></p>`,
            deep: '<p>This is often the slowest hop: authoritative servers can be anywhere in the world, while root and TLD servers are heavily anycast. Big DNS hosting providers anycast their authoritative servers too.</p>',
            actions: [{ send: ['resolver', 'auth'], pkt: qAuth, ms: 35 }],
          });
          if (o.tc) {
            S.push({
              title: 'Truncated! (TC=1)',
              focus: ['auth', 'resolver'],
              text: '<p>The authoritative server signals that the full response didn\'t fit in the UDP size the resolver advertised. It sets <b>TC=1</b> (truncated) and returns no usable answer. The resolver must retry over <b>TCP</b>.</p>',
              deep: '<p>Large responses (many records, big DNSSEC signatures, long TXT records) exceed 1232 bytes. Fragmented UDP is fragile: firewalls drop fragments, and fragments can be spoofed. Since RFC 7766, TCP support is <b>mandatory</b> for all DNS implementations.</p>',
              actions: [{ send: ['auth', 'resolver'], pkt: rAuthTC, ms: 35, tone: 'warn' }, { badge: 'resolver', text: 'TC=1 → retry over TCP', tone: 'warn' }],
            });
            S.push({
              title: 'Retry over TCP port 53',
              focus: ['resolver', 'auth'],
              text: '<p>A TCP three-way handshake (SYN, SYN-ACK, ACK) costs one extra round trip. Then the same query is sent over the connection, prefixed with a 2-byte length field.</p>',
              deep: '<p>Resolvers may keep the TCP connection open for further queries (RFC 7828 <code>edns-tcp-keepalive</code>). DNS over TLS (port 853) builds on the same TCP framing.</p>',
              actions: [
                { send: ['resolver', 'auth'], pkt: tcp('SYN', R.ip4, authIp4, 40112, 53), ms: 35, tone: 'gen', bend: 20 },
                { send: ['auth', 'resolver'], pkt: tcp('SYN, ACK', authIp4, R.ip4, 53, 40112), ms: 35, tone: 'gen', bend: 20 },
                { link: ['resolver', 'auth'], id: 'tcp', tone: 'gen', label: 'TCP :53', dy: -18 },
                { send: ['resolver', 'auth'], pkt: qAuthTcp, ms: 35 },
              ],
            });
          }
          S.push({
            title: 'Authoritative answer (AA=1)',
            focus: ['auth', 'resolver'],
            text: `<p>The answer: <code>${host}. ${TTL} IN ${qt} ${data}</code>. The <b>AA</b> (Authoritative Answer) flag is set because this server owns the zone data.</p><p>The resolver caches the record for its TTL of ${TTL} seconds.</p>`,
            deep: '<p>The answer section may hold several records (round-robin load balancing), or a CNAME chain that the resolver has to follow; see the Record Types lesson. Modern servers use "minimal responses", so they no longer repeat the NS set in the authority section.</p>',
            actions: [
              { send: ['auth', 'resolver'], pkt: o.tc ? rAuthTcp : rAuth, ms: 35 },
              { badge: 'auth', text: 'AA=1 authoritative', tone: 'ok' },
              { cache: 'resolver', add: [{ name, type: qt, data, ttl: TTL }] },
              ...(o.tc ? [{ unlink: 'tcp' }] : []),
            ],
          });
        }

        S.push({
          title: 'Resolver answers the stub (RA=1)',
          focus: ['resolver', 'stub'],
          text: `<p>The resolver returns the answer to the stub, <b>reusing the stub's transaction ID</b> and replying to the same source port. The flags read <b>QR=1 RD=1 RA=1</b>, and AA is <b>0</b>: the resolver isn't authoritative, it's passing on what it learned.</p>`,
          deep: '<p>The stub checks the source IP, the ports, the transaction ID and the question section before accepting the reply. Anything that doesn\'t match is silently dropped.</p>',
          actions: [
            { send: ['resolver', 'stub'], pkt: rStub, ms: 6 },
            { badge: 'stub', text: `ID ${D.hex4(q1.dns.id)} matches ✓`, tone: 'ok' },
            { cache: 'stub', title: 'OS cache', add: [{ name, type: qt, data, ttl: hit ? TTL - age : TTL }] },
          ],
        });
        S.push({
          title: 'Back to the browser',
          focus: ['stub', 'browser'],
          text: `<p><code>getaddrinfo()</code> returns a list of socket addresses to the browser, and the OS and browser caches both store the result. <b>DNS is done.</b> ${hit ? 'Thanks to the resolver cache, the whole lookup took only a few milliseconds.' : 'The whole lookup took roughly the sum of every round trip, shown in the lookup-time counter.'}</p>`,
          actions: [
            { send: ['stub', 'browser'], tone: 'ipc', bend: 0, label: data, pkt: ipc(`getaddrinfo() → ${data}`, data, [['Return value', '0 (success)'], ['ai_family', qt === 'A' ? 'AF_INET' : 'AF_INET6'], ['ai_addr', `${data} port 443`]]) },
            { cache: 'browser', add: [{ name, type: qt, data, ttl: 60 }] },
            { badge: 'browser', text: `${host} → ${data}`, tone: 'ok' },
          ],
        });
      }

      S.push({
        title: 'Use the answer: connect!',
        focus: ['browser', 'web'],
        text: `<p>With the address in hand, the browser opens a <b>TCP connection to ${data} port 443</b> (or a QUIC connection), then does a TLS handshake and sends the HTTP request. DNS only gives you an <i>address</i>. The name comes back later in the TLS <b>SNI</b> and the HTTP <b>Host</b> header, so the server knows which site you want.</p><p>The next lesson, <a href="#connect">Using the answer</a>, animates that part.</p>`,
        actions: [
          { show: ['web'] },
          { send: ['browser', 'web'], pkt: tcp('SYN', qt === 'A' ? C.ip4 : C.ip6, data, 50514, 443, qt === 'A' ? 4 : 6), tone: 'gen', label: 'TCP SYN → :443' },
          { overlay: { id: 'done', at: 'top', cls: 'ok', title: 'Resolution complete', html: `<code>${host}</code> → <code>${data}</code><br><span class="small muted">Queries sent by the resolver: ${o.cache === 'cold' ? (o.tc ? 4 : 3) : o.cache === 'tld' ? (o.tc ? 3 : 2) : 0}</span>` } },
        ],
      });

      return {
        nodes, links, groups, setup, steps: S, hud: 'lookup',
        intro: `Resolving <code>${host}</code> (${qt}) with a <b>${{ cold: 'cold', tld: 'partly warm', hit: 'warm', browser: 'browser-cached' }[o.cache]}</b> cache${o.qmin ? ' and QNAME minimisation' : ''}${o.tc ? ' and a truncated response' : ''}. Press <b>Play</b> or <b>Next →</b>.`,
      };
    },
  });
})();
