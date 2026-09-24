/* Section 8 — Attacks: classic and Kaminsky cache poisoning, reflection/amplification DDoS, and the defences. */
(function () {
  'use strict';
  const DV = window.DV;
  const D = DV.dns, N = DV.net, Wd = DV.world;
  const rr = D.rr;
  const C = Wd.client, R = Wd.resolver, A = Wd.auth, EV = Wd.attacker;
  const KE = Wd.keys.ex;

  function poison(o) {
    const kam = o.attack === 'kaminsky';
    const def = o.def;
    const rnd = 'x7f3q.example.com';
    const target = kam ? rnd : 'www.example.com';
    const sport = def === 'port' ? 38127 : 53;
    const txid = 0x5b2e;
    const poisoned = def === 'none';
    const nodes = [
      { id: 'victim', x: 100, y: 130, icon: 'laptop', tier: 'client', label: 'Victim', sub: C.ip4 },
      { id: 'attacker', x: 100, y: 430, icon: 'attacker', tier: 'evil', label: 'Attacker', sub: `${EV.ip4}<br>can spoof source IPs` },
      { id: 'resolver', x: 450, y: 250, icon: 'resolver', tier: 'resolver', label: 'Recursive resolver', sub: R.ip4, cacheAt: 'below' },
      { id: 'auth', x: 860, y: 250, icon: 'auth', tier: 'auth', label: 'ns1.example.com', sub: `${A.ip4}<br>(far away: 80 ms RTT)` },
      { id: 'fake', x: 860, y: 470, icon: 'web', tier: 'evil', label: kam ? "Attacker's NS & fake site" : "Attacker's fake site", sub: EV.ip4, hidden: true, size: 'sm' },
    ];
    const links = [['victim', 'resolver'], ['attacker', 'resolver'], ['resolver', 'auth'], ['victim', 'fake']];
    const groups = [{ x: 15, y: 330, w: 190, h: 215, label: 'Attacker', cls: 'evil' }];
    const trig = D.query({ src: EV.ip4, dst: R.ip4, name: target, type: 'A', note: kam ? 'A random name that is certainly not cached, so the resolver must send a query upstream. The attacker can repeat this endlessly with new names.' : 'The attacker times this for the moment the cached www.example.com record expires.' });
    const up = D.query({ src: R.ip4, dst: A.ip4, name: target, type: 'A', rd: 0, id: txid, sport, do: def === 'dnssec',
      note: def === 'port' ? 'Random source port (38127) and random ID: 32 bits of entropy (RFC 5452).' : 'Fixed source port 53: only the 16-bit ID protects this query, as in pre-2008 resolvers.' });
    const forgedAns = kam
      ? { an: [rr(rnd, 86400, 'A', EV.ip4)], ns: [rr('example.com', 86400, 'NS', 'ns.attacker.example.')], ar: [rr('ns.attacker.example', 86400, 'A', EV.ip4)] }
      : { an: [rr('www.example.com', 86400, 'A', EV.ip4)] };
    const forged = D.response(up, Object.assign({ aa: 1, src: A.ip4, forged: true, note: kam ? 'The payload is in the AUTHORITY section: it claims ns.attacker.example is the name server for the WHOLE example.com zone. The source IP is spoofed as ns1.example.com.' : 'A forged answer for www.example.com with a spoofed source IP.' }, forgedAns));
    const real = D.response(up, { aa: 1, an: kam ? [] : [rr('www.example.com', 3600, 'A', Wd.web.ip4), ...(def === 'dnssec' ? [rr('www.example.com', 3600, 'RRSIG', D.rrsig('A', 13, 3, 3600, KE.zsk.tag, 'example.com'))] : [])],
      rcode: kam ? 'NXDOMAIN' : 'NOERROR', ns: kam ? [rr('example.com', 300, 'SOA', 'ns1.example.com. hostmaster.example.com. 2026092401 7200 3600 1209600 300')] : [], note: 'The genuine response. It arrives later because ns1.example.com is far away.' });
    const guesses = Array.from({ length: 18 }, (_, i) => 'ID ' + D.hex4((0x5b10 + i * 1) & 0xffff).slice(2));
    const vq = D.query({ src: C.ip4, dst: R.ip4, name: 'www.example.com', type: 'A' });
    const vqUp = D.query({ src: R.ip4, dst: EV.ip4, name: 'www.example.com', type: 'A', rd: 0 });
    const vqUpR = D.response(vqUp, { aa: 1, an: [rr('www.example.com', 86400, 'A', EV.ip4)], note: "Answered by the attacker's name server, which the resolver now believes is authoritative for example.com." });
    const vr = D.response(vq, { ra: 1, an: [rr('www.example.com', poisoned ? 86400 : 3600, 'A', poisoned ? EV.ip4 : Wd.web.ip4)] });
    const vqUp2 = D.query({ src: R.ip4, dst: A.ip4, name: 'www.example.com', type: 'A', rd: 0 });
    const vqUp2R = D.response(vqUp2, { aa: 1, an: [rr('www.example.com', 3600, 'A', Wd.web.ip4)] });

    const S = [];
    S.push({
      title: kam ? 'Attacker asks for a random, uncached name' : 'Attacker waits for the TTL to expire, then asks',
      focus: ['attacker', 'resolver'],
      text: kam
        ? '<p>In <b>Dan Kaminsky\'s 2008 attack</b>, the attacker makes the resolver look up a name that <b>cannot be cached</b>, such as <code>x7f3q.example.com</code>. If this attempt fails, the attacker simply tries <code>x7f3r</code>, <code>x7f3s</code>… with no waiting.</p>'
        : '<p>The attacker wants to poison <code>www.example.com</code>. While a real answer is cached the resolver won\'t ask upstream, so the attacker gets <b>one attempt per TTL</b> (here once an hour) and triggers a lookup right after the cached record expires.</p>',
      deep: '<p>The attacker needs a way to make the resolver send queries: an open resolver, a client account on the same network, or a web page or email that makes the victim\'s own computer look up names.</p>',
      actions: [{ send: ['attacker', 'resolver'], pkt: trig, tone: 'bad' }],
    });
    S.push({
      title: 'Resolver sends a query upstream',
      focus: ['resolver', 'auth'],
      text: `<p>The resolver asks ns1.example.com and waits. It will accept the <b>first</b> response that matches the <b>destination port</b> (${sport}) and the <b>transaction ID</b> (0x5b2e), and that comes from the right server address and echoes the question.</p>`,
      actions: [
        { send: ['resolver', 'auth'], pkt: up, dur: 2600 },
        { badge: 'resolver', text: `waiting: ID 0x5b2e, port ${sport}`, tone: 'info' },
      ],
    });
    S.push({
      title: 'The race: a flood of forged replies',
      focus: ['attacker', 'resolver'],
      text: `<p>Before the genuine reply can arrive, the attacker sends many forged responses with the source address <b>spoofed</b> as ns1.example.com (<code>${A.ip4}</code>), each guessing a different transaction ID${def === 'port' ? ' <i>and</i> port' : ''}.${kam ? ' The payload hides in the <b>authority section</b>: "ns.attacker.example is the name server for all of example.com".' : ''}</p>`,
      deep: def === 'port'
        ? '<p>With a random 16-bit port and a random 16-bit ID, each forged packet has about a 1 in 4 billion chance. Resolvers can also randomise the case of the query name (<b>0x20 encoding</b>, e.g. <code>wWw.ExAmPlE.cOm</code>) and require the reply to echo it exactly, adding more entropy.</p>'
        : '<p>Before 2008, many resolvers sent all queries from one fixed port, so only the 16-bit ID stood between an attacker and the cache: 65,536 possibilities. Over enough attempts that is a certain win.</p>',
      actions: [
        { burst: ['attacker', 'resolver'], n: 18, gap: 90, dur: 1000, tone: 'bad', pkt: forged, labels: guesses, logLabel: '18× forged responses' },
        { overlay: { id: 'odds', at: 'tr', cls: def === 'none' ? 'bad' : 'ok', title: 'Attacker\'s odds per forged packet', html: def === 'port' ? '<span class="stat">1 / 4,294,967,296</span><div class="small">16-bit ID × 16-bit port</div>' : '<span class="stat">1 / 65,536</span><div class="small">16-bit ID only, fixed port</div>' } },
      ],
    });
    if (def === 'none') {
      S.push({
        title: 'One guess matches: the forged reply is accepted',
        focus: ['resolver'],
        text: `<p>One forged packet had ID 0x5b2e. It arrives before the real one and matches everything the resolver checks, so the resolver <b>accepts it and caches it</b>. When the genuine response arrives a moment later, there is no outstanding query left to match it, so it is <b>discarded</b>.</p>`,
        actions: [
          { badge: 'resolver', text: '✓ ID 0x5b2e matched: accepted!', tone: 'bad' },
          { cls: ['resolver', 'compromised'] },
          { cache: 'resolver', title: 'Resolver cache', add: kam
            ? [{ name: 'example.com.', type: 'NS', data: 'ns.attacker.example.', ttl: 86400, tone: 'bad' }, { name: 'ns.attacker.example.', type: 'A', data: EV.ip4, ttl: 86400, tone: 'bad' }]
            : [{ name: 'www.example.com.', type: 'A', data: EV.ip4, ttl: 86400, tone: 'bad' }] },
          { send: ['auth', 'resolver'], pkt: real, tone: 'gen' },
          { badge: 'resolver', text: 'real reply: no matching query → dropped', tone: 'warn' },
        ],
      });
    } else {
      S.push({
        title: def === 'port' ? 'Every forged reply misses' : 'Forged reply fails DNSSEC validation',
        focus: ['resolver'],
        text: def === 'port'
          ? '<p>The forged packets have the wrong destination port and/or ID, so they are <b>silently dropped</b>. The genuine answer arrives and is cached. To have a realistic chance the attacker would need billions of packets per query attempt.</p>'
          : '<p>Suppose the attacker gets lucky and one forged packet matches the port and ID. The resolver validates with DNSSEC: the forged records have <b>no valid RRSIG</b> from example.com\'s key, so they are <b>bogus and discarded</b>. The genuine, signed answer arrives and validates.</p>',
        deep: def === 'dnssec' ? '<p>DNSSEC is the only defence that holds even against an <b>on-path</b> attacker, who can see the port and ID and doesn\'t need to guess them. Randomisation only defeats <i>off-path</i> (blind) attackers.</p>' : '',
        actions: [
          { badge: 'resolver', text: def === 'port' ? '✗ port/ID mismatch → dropped' : '✗ no valid RRSIG → bogus', tone: 'ok' },
          { cls: ['resolver', 'shielded'] },
          { send: ['auth', 'resolver'], pkt: real },
          { cache: 'resolver', title: 'Resolver cache', add: kam ? [{ name: rnd + '.', type: 'A', data: 'NXDOMAIN', ttl: 300, tone: 'warn' }] : [{ name: 'www.example.com.', type: 'A', data: Wd.web.ip4, ttl: 3600 }] },
        ],
      });
    }
    S.push({
      title: poisoned ? 'The victim is sent to the attacker' : 'The victim gets the real address',
      focus: poisoned ? ['victim', 'resolver', 'fake'] : ['victim', 'resolver'],
      text: poisoned
        ? (kam
          ? '<p>Later the victim looks up <code>www.example.com</code>, a name the attacker never forged directly. The resolver now believes <code>ns.attacker.example</code> is authoritative for the <b>whole zone</b>, asks it, and gets the attacker\'s IP. <b>Every name under example.com is hijacked</b> for the 24-hour TTL.</p>'
          : '<p>The victim looks up <code>www.example.com</code> and gets the attacker\'s address straight from the poisoned cache. So does every other user of this resolver, for as long as the forged TTL lasts.</p>')
          + '<p>The last line of defence is <b>TLS</b>: the fake site can\'t present a valid certificate for www.example.com, unless the attacker also used the poisoned DNS to pass a CA\'s domain validation.</p>'
        : '<p>The cache holds only genuine data, and the victim connects to the real <code>203.0.113.10</code>. Try the <b>None</b> defence above to see the attack succeed.</p>',
      actions: poisoned
        ? [
          { send: ['victim', 'resolver'], pkt: vq },
          ...(kam ? [{ show: ['fake'] }, { send: ['resolver', 'fake'], pkt: vqUp, tone: 'bad' }, { send: ['fake', 'resolver'], pkt: vqUpR, tone: 'bad' }] : []),
          { send: ['resolver', 'victim'], pkt: vr, tone: 'bad' },
          { show: ['fake'] },
          { send: ['victim', 'fake'], tone: 'bad', label: 'HTTPS → fake site', pkt: N.tcp('SYN', C.ip4, EV.ip4, 50514, 443) },
          { badge: 'victim', text: '⚠ certificate warning (if lucky)', tone: 'bad' },
        ]
        : [
          { send: ['victim', 'resolver'], pkt: vq },
          ...(kam ? [{ send: ['resolver', 'auth'], pkt: vqUp2 }, { send: ['auth', 'resolver'], pkt: vqUp2R }] : []),
          { send: ['resolver', 'victim'], pkt: vr },
          { badge: 'victim', text: 'www.example.com → 203.0.113.10 ✓', tone: 'ok' },
        ],
    });
    S.push({
      title: 'Defences in depth',
      focus: ['resolver'],
      text: '<p>Real resolvers stack several defences. Compare the scenarios using the <b>Defence</b> selector above.</p>',
      actions: [{ overlay: { id: 'd', at: 'tr', w: 460, title: 'Cache-poisoning defences', html: '<table><tr><th>Defence</th><th>Stops</th></tr><tr><td>Random source port + ID (RFC 5452)</td><td>blind off-path spoofing</td></tr><tr><td>0x20 case randomisation</td><td>adds entropy</td></tr><tr><td>Bailiwick checks (ignore out-of-zone records)</td><td>unrelated NS/glue injection</td></tr><tr><td>DNS cookies (RFC 7873)</td><td>off-path spoofing</td></tr><tr><td><b>DNSSEC validation</b></td><td>all forgery, including on-path</td></tr><tr><td>Encrypted transport (DoT/DoH)</td><td>tampering on that hop</td></tr></table>' } }],
    });
    return { nodes, links, groups, steps: S, setup: [{ cache: 'resolver', title: 'Resolver cache', add: [] }],
      intro: `${kam ? 'Kaminsky-style' : 'Classic'} cache poisoning against a resolver with <b>${{ none: 'no defences (fixed port)', port: 'source-port randomization', dnssec: 'DNSSEC validation' }[def]}</b>.` };
  }

  function amp(o) {
    const safe = o.defamp === 'bcp38';
    const VIC = '203.0.113.80';
    const nodes = [
      { id: 'bot', x: 100, y: 280, icon: 'botnet', tier: 'evil', label: 'Botnet', sub: 'spoofs source = victim' },
      { id: 'edge', x: 290, y: 280, icon: 'router', tier: 'neutral', label: 'ISP edge router', sub: 'BCP 38 filter', hidden: !safe, size: 'sm' },
      { id: 'r1', x: 560, y: 100, icon: 'resolver', tier: 'resolver', label: 'Open resolver', sub: '198.51.100.11', size: 'sm' },
      { id: 'r2', x: 560, y: 280, icon: 'resolver', tier: 'resolver', label: 'Open resolver', sub: '198.51.100.12', size: 'sm' },
      { id: 'r3', x: 560, y: 460, icon: 'resolver', tier: 'resolver', label: 'Open resolver', sub: '198.51.100.13', size: 'sm' },
      { id: 'victim', x: 880, y: 280, icon: 'victim', tier: 'web', label: 'Victim server', sub: VIC },
    ];
    const links = [['bot', 'r1'], ['bot', 'r2'], ['bot', 'r3'], ['r1', 'victim'], ['r2', 'victim'], ['r3', 'victim']];
    const q = D.query({ src: VIC, dst: '198.51.100.11', name: 'example.com', type: 'ANY', edns: { udp: 4096 }, note: 'Source IP forged to be the VICTIM\'s. A ~60-byte query asking for as much data as possible (ANY, or DNSKEY/TXT on a large signed zone).' });
    q.forged = true;
    const big = D.response(q, { ra: 1, an: [
      rr('example.com', 3600, 'SOA', 'ns1.example.com. hostmaster.example.com. 2026092401 7200 3600 1209600 300'),
      rr('example.com', 3600, 'DNSKEY', D.dnskey(KE.ksk, true)), rr('example.com', 3600, 'DNSKEY', D.dnskey(KE.zsk, false)),
      rr('example.com', 3600, 'TXT', '"' + 'v=spf1 include:_spf.a.example include:_spf.b.example include:_spf.c.example ~all' + '"'),
      rr('example.com', 3600, 'TXT', '"' + 'x'.repeat(240) + '"'),
      rr('example.com', 3600, 'RRSIG', D.rrsig('DNSKEY', 13, 2, 3600, KE.ksk.tag, 'example.com')),
      rr('example.com', 3600, 'RRSIG', D.rrsig('TXT', 13, 2, 3600, KE.zsk.tag, 'example.com')),
    ], note: 'A large response sent to the forged source address, i.e. to the victim, who never asked for it. Real attack responses are often 3–4 KB.' });
    const S = [];
    if (!safe) {
      S.push({
        title: 'Small spoofed queries to many open resolvers',
        focus: ['bot', 'r1', 'r2', 'r3'],
        text: '<p>Thousands of bots send tiny DNS queries to <b>open resolvers</b> (resolvers that answer anyone on the Internet), with the <b>source IP forged</b> as the victim\'s address. UDP has no handshake, so nothing checks that the source is genuine.</p>',
        actions: [{ par: [
          { burst: ['bot', 'r1'], n: 8, gap: 120, dur: 900, tone: 'bad', pkt: q, logLabel: 'spoofed queries (~60 B)' },
          { burst: ['bot', 'r2'], n: 8, gap: 120, dur: 900, tone: 'bad' },
          { burst: ['bot', 'r3'], n: 8, gap: 120, dur: 900, tone: 'bad' },
        ] }],
      });
      S.push({
        title: 'Big answers all go to the victim',
        focus: ['r1', 'r2', 'r3', 'victim'],
        text: '<p>Each resolver answers the <i>apparent</i> sender, which is the victim. Every ~60-byte query produces a response of several kilobytes: the <b>amplification factor</b>. Multiply that by thousands of resolvers and bots.</p>',
        actions: [
          { par: [
            { burst: ['r1', 'victim'], n: 10, gap: 90, dur: 1000, tone: 'warn', big: true, pkt: big, logLabel: 'amplified responses (~3 KB)' },
            { burst: ['r2', 'victim'], n: 10, gap: 90, dur: 1000, tone: 'warn', big: true },
            { burst: ['r3', 'victim'], n: 10, gap: 90, dur: 1000, tone: 'warn', big: true },
          ] },
          { overlay: { id: 'af', at: 'tl', cls: 'bad', title: 'Amplification', html: '<div>query <b>~60 B</b> → response <b>~3,000 B</b></div><span class="stat">≈ 50×</span><div class="small">10 Gbit/s of bot traffic → ~500 Gbit/s at the victim</div>' } },
        ],
      });
      S.push({
        title: 'Victim\'s link is saturated',
        focus: ['victim'],
        text: '<p>The victim is flooded with DNS responses it never asked for. Its uplink fills up and legitimate users can\'t get through. The victim doesn\'t even need to run DNS to be hit.</p>',
        actions: [{ cls: ['victim', 'down'] }, { badge: 'victim', text: '🔥 link saturated', tone: 'bad' }],
      });
      S.push({
        title: 'Why it works, and how to fix it',
        focus: ['bot', 'r1', 'r2', 'r3'],
        text: '<p>Three ingredients: <b>spoofable source addresses</b>, <b>open resolvers</b>, and <b>large responses</b>. Take away any one of them and the attack falls apart. Switch the defence option to <b>BCP 38 + closed resolvers + RRL</b> to see how.</p>',
        actions: [],
      });
    } else {
      S.push({
        title: 'Spoofed packets dropped at the source network',
        focus: ['bot', 'edge'],
        text: '<p>With <b>BCP 38 / RFC 2827 ingress filtering</b>, the bots\' ISP drops any packet whose source address doesn\'t belong to the customer network it came from. Spoofed queries never reach the Internet.</p>',
        actions: [{ burst: ['bot', 'edge'], n: 10, gap: 100, dur: 700, tone: 'bad', pkt: q, logLabel: 'spoofed queries' }, { badge: 'edge', text: '✗ dropped: source not in customer prefix', tone: 'ok' }],
      });
      S.push({
        title: 'Resolvers refuse strangers; servers rate-limit',
        focus: ['r1', 'r2', 'r3', 'victim'],
        text: '<p>Not every network filters, so some spoofed packets still get through. But properly configured resolvers are <b>closed</b>: they answer only their own clients (tiny REFUSED responses, or nothing). Authoritative servers use <b>Response Rate Limiting</b>: repeated identical answers to one address are dropped or "slipped" as truncated TC=1 replies, which pushes real clients to TCP, a handshake that spoofers cannot complete.</p>',
        deep: '<p>Other measures: minimal responses to ANY queries (RFC 8482), DNS cookies (RFC 7873), smaller EDNS buffer sizes (1232 bytes), and upstream DDoS scrubbing.</p>',
        actions: [
          { par: [
            { burst: ['r1', 'victim'], n: 3, gap: 200, dur: 900, tone: 'ok' },
            { burst: ['r2', 'victim'], n: 3, gap: 200, dur: 900, tone: 'ok' },
            { burst: ['r3', 'victim'], n: 3, gap: 200, dur: 900, tone: 'ok' },
          ] },
          { badge: 'r2', text: 'REFUSED / rate-limited', tone: 'ok' },
          { badge: 'victim', text: 'normal traffic ✓', tone: 'ok' },
          { cls: ['victim', 'shielded'] },
        ],
      });
      S.push({
        title: 'Defence summary',
        focus: ['edge', 'r2'],
        text: '<p>Most defences only work if <i>other</i> networks deploy them, which makes this a shared-responsibility problem. Projects such as MANRS track anti-spoofing adoption.</p>',
        actions: [{ overlay: { id: 'd', at: 'tl', w: 440, title: 'Amplification defences', html: '<table><tr><td>BCP 38 ingress filtering</td><td>no spoofed sources</td></tr><tr><td>Closed resolvers</td><td>no reflectors</td></tr><tr><td>RRL / TC=1 slip</td><td>limits reflected volume</td></tr><tr><td>Minimal ANY (RFC 8482)</td><td>smaller responses</td></tr><tr><td>DNS cookies (RFC 7873)</td><td>verifies returning clients</td></tr></table>' } }],
      });
    }
    return { nodes, links: safe ? [['bot', 'edge'], ['edge', 'r1'], ['edge', 'r2'], ['edge', 'r3'], ['r1', 'victim'], ['r2', 'victim'], ['r3', 'victim']] : links, steps: S,
      intro: safe ? 'The same amplification attempt against well-run networks.' : 'A reflection/amplification DDoS: spoofed small queries become a flood of large answers aimed at the victim.' };
  }

  DV.register({
    id: 'attacks',
    nav: 'Attacks & defences',
    title: 'Attacks: spoofing, poisoning & amplification',
    icon: 'attack',
    blurb: 'Race forged replies against a resolver (classic and Kaminsky cache poisoning), see how port randomization and DNSSEC stop them, and watch a reflection/amplification DDoS.',
    intro: '<p>Classic DNS runs over <b>UDP</b> with no authentication: a reply is accepted if it <i>looks</i> right. Attackers exploit this by <b>forging answers</b> to poison caches, or by <b>forging questions</b> to reflect traffic at a victim.</p>',
    options: [
      { id: 'attack', type: 'segmented', label: 'Attack', value: 'kaminsky', choices: [['classic', 'Classic poisoning'], ['kaminsky', 'Kaminsky (2008)'], ['amp', 'Amplification DDoS']] },
      { id: 'def', type: 'segmented', label: 'Defence', value: 'none', choices: [['none', 'None'], ['port', 'Port randomization'], ['dnssec', 'DNSSEC']], visibleIf: (o) => o.attack !== 'amp' },
      { id: 'defamp', type: 'segmented', label: 'Defence', value: 'none', choices: [['none', 'None'], ['bcp38', 'BCP 38 + closed resolvers + RRL']], visibleIf: (o) => o.attack === 'amp' },
    ],
    build(o) {
      return o.attack === 'amp' ? amp(o) : poison(o);
    },
  });
})();
