/* Section 3 — Caching & TTL: positive caching, TTL countdown, expiry, and negative caching. */
(function () {
  'use strict';
  const DV = window.DV;
  const D = DV.dns, Wd = DV.world;
  const rr = D.rr;
  const C = Wd.client, C2 = Wd.client2, R = Wd.resolver, A = Wd.auth;
  const SOA = 'ns1.example.com. hostmaster.example.com. 2026092401 7200 3600 1209600 300';

  function nodes() {
    return [
      { id: 'alice', x: 100, y: 130, icon: 'laptop', tier: 'client', label: "Alice's laptop", sub: C.ip4, cacheAt: 'right' },
      { id: 'bob', x: 100, y: 430, icon: 'phone', tier: 'client', label: "Bob's phone", sub: C2.ip4, cacheAt: 'right' },
      { id: 'resolver', x: 560, y: 300, icon: 'resolver', tier: 'resolver', label: 'Shared recursive resolver', sub: R.ip4, cacheAt: 'above' },
      { id: 'auth', x: 870, y: 270, icon: 'auth', tier: 'auth', label: 'ns1.example.com', sub: `${A.ip4}<br>(authoritative)` },
    ];
  }
  const links = [['alice', 'resolver'], ['bob', 'resolver'], ['resolver', 'auth']];
  const fmtT = (t) => (t >= 3600 ? t / 3600 + ' h' : t >= 60 ? t / 60 + ' min' : t + ' s');

  function positive(o) {
    const T = +o.ttl;
    const name = 'www.example.com.', ip = Wd.web.ip4;
    const q1 = D.query({ src: C.ip4, dst: R.ip4, name, type: 'A' });
    const qa = D.query({ src: R.ip4, dst: A.ip4, name, type: 'A', rd: 0, note: 'The .com NS and example.com NS records are already cached (TTL 2 days), so the resolver goes straight to the authoritative server.' });
    const ra = D.response(qa, { aa: 1, an: [rr(name, T, 'A', ip)], note: `The zone owner chose TTL = ${T} s for this record.` });
    const r1 = D.response(q1, { ra: 1, an: [rr(name, T, 'A', ip)] });
    const qb = D.query({ src: C2.ip4, dst: R.ip4, name, type: 'A' });
    const rb = D.response(qb, { ra: 1, an: [rr(name, T - 40, 'A', ip)], note: `Served from cache 40 s after it was stored, so the TTL now reads ${T - 40} s, not ${T}. Downstream caches can never keep it past the original expiry time.` });
    const q3 = D.query({ src: C.ip4, dst: R.ip4, name, type: 'A' });
    const qa3 = D.query({ src: R.ip4, dst: A.ip4, name, type: 'A', rd: 0 });
    const ra3 = D.response(qa3, { aa: 1, an: [rr(name, T, 'A', ip)] });
    const r3 = D.response(q3, { ra: 1, an: [rr(name, T, 'A', ip)] });
    const S = [
      {
        title: 'Alice: first lookup (cold cache)',
        focus: ['alice', 'resolver', 'auth'],
        text: `<p>Alice opens <code>www.example.com</code>. Neither her laptop nor the resolver has it cached, so the resolver asks the authoritative server. (The root and .com referrals are assumed to be cached already; they have 2-day TTLs.)</p>`,
        actions: [
          { lookup: 'reset' },
          { send: ['alice', 'resolver'], pkt: q1, ms: 6 },
          { badge: 'resolver', text: 'cache MISS', tone: 'bad' },
          { send: ['resolver', 'auth'], pkt: qa, ms: 35 },
        ],
      },
      {
        title: `Answer with TTL ${T} s gets cached along the way`,
        focus: ['auth', 'resolver', 'alice'],
        text: `<p>The authoritative answer carries <b>TTL = ${T} s</b> (${fmtT(T)}). The resolver stores it and so does Alice's OS. Watch the TTL bars: each cache counts down from the moment it stored the record.</p>`,
        deep: '<p>The TTL is a 32-bit number of seconds (RFC 2181 caps it at 2<sup>31</sup>−1). Resolvers usually also clamp TTLs to a configured maximum, often 1 day (Unbound <code>cache-max-ttl</code>, BIND <code>max-cache-ttl</code>), and sometimes to a minimum.</p>',
        actions: [
          { send: ['auth', 'resolver'], pkt: ra, ms: 35 },
          { cache: 'resolver', title: 'Resolver cache', add: [{ name, type: 'A', data: ip, ttl: T }] },
          { badge: 'auth', text: 'queries answered: 1', tone: 'info', sticky: true },
          { send: ['resolver', 'alice'], pkt: r1, ms: 6 },
          { cache: 'alice', title: 'OS cache', add: [{ name, type: 'A', data: ip, ttl: T }] },
          { badge: 'alice', text: 'lookup: 82 ms', tone: 'info' },
        ],
      },
      {
        title: '10 seconds later: Alice reloads (local hit)',
        focus: ['alice'],
        text: '<p>Alice refreshes the page. Her own OS cache still holds the record, so <b>no packet leaves the laptop</b> and the lookup costs about 0 ms.</p>',
        actions: [{ lookup: 'reset' }, { advance: 10 }, { badge: 'alice', text: 'local cache HIT · 0 ms', tone: 'ok' }],
      },
      {
        title: '30 seconds later: Bob benefits from the shared cache',
        focus: ['bob', 'resolver'],
        text: `<p>Bob, on the same network, looks up the same name. His phone has nothing cached, but the <b>resolver</b> does, so he gets an answer in ~12 ms instead of ~82 ms. Look at the TTL in the reply: <b>${T - 40} s</b>. The resolver hands out the <i>remaining</i> lifetime, not the original ${T} s.</p>`,
        actions: [
          { lookup: 'reset' },
          { advance: 30 },
          { send: ['bob', 'resolver'], pkt: qb, ms: 6 },
          { badge: 'resolver', text: 'cache HIT ✓', tone: 'ok' },
          { send: ['resolver', 'bob'], pkt: rb, ms: 6 },
          { cache: 'bob', title: 'OS cache', add: [{ name, type: 'A', data: ip, ttl: T - 40 }] },
          { badge: 'bob', text: `TTL ${T - 40} s · 12 ms`, tone: 'ok' },
        ],
      },
      {
        title: 'Time passes… every copy expires together',
        focus: ['alice', 'bob', 'resolver'],
        text: `<p>We fast-forward ${fmtT(T - 35)}. Because the countdown carries over between caches, <b>every copy of the record expires at the same moment</b>: exactly ${fmtT(T)} after the authoritative server sent it. Expired entries can no longer be used.</p>`,
        deep: '<p><b>Serve-stale</b> (RFC 8767) lets a resolver keep answering with expired data when the authoritative servers can\'t be reached, which avoids an outage caused by an authoritative-side failure.</p>',
        actions: [{ advance: T - 35, dur: 2600 }],
      },
      {
        title: 'Alice again: expired, so fetch a fresh copy',
        focus: ['alice', 'resolver', 'auth'],
        text: '<p>Alice\'s next lookup misses locally, misses at the resolver, and goes to the authoritative server again. The TTL bars start over. If the zone owner had changed the IP address, this is the moment clients would see the new one.</p>',
        actions: [
          { lookup: 'reset' },
          { send: ['alice', 'resolver'], pkt: q3, ms: 6 },
          { send: ['resolver', 'auth'], pkt: qa3, ms: 35 },
          { send: ['auth', 'resolver'], pkt: ra3, ms: 35 },
          { badge: 'auth', text: 'queries answered: 2', tone: 'info', sticky: true },
          { cache: 'resolver', add: [{ name, type: 'A', data: ip, ttl: T }] },
          { send: ['resolver', 'alice'], pkt: r3, ms: 6 },
          { cache: 'alice', add: [{ name, type: 'A', data: ip, ttl: T }] },
        ],
      },
      {
        title: 'Choosing a TTL is a trade-off',
        focus: ['auth'],
        text: '<p>Short TTLs mean changes spread fast (failover, migrations), but you get more queries and more cache misses. Long TTLs are efficient and resilient, but a change can take hours to reach everyone. <b>Operational tip:</b> lower the TTL a day <i>before</i> a planned change, make the change, then raise it again.</p><p>Try the other TTL settings above and compare.</p>',
        actions: [{ overlay: { id: 'trade', at: 'bl', title: `TTL = ${fmtT(T)}`, html: `<table><tr><th></th><th>Short (60 s)</th><th>Long (1 h+)</th></tr><tr><td>Change propagation</td><td class="good">fast</td><td class="warnc">slow</td></tr><tr><td>Cache hit rate</td><td class="warnc">lower</td><td class="good">higher</td></tr><tr><td>Load on auth servers</td><td class="warnc">higher</td><td class="good">lower</td></tr><tr><td>Survives auth outage</td><td class="warnc">briefly</td><td class="good">longer</td></tr></table>` } }],
      },
    ];
    return { nodes: nodes(), links, steps: S, hud: 'both', setup: [{ cache: 'resolver', title: 'Resolver cache', add: [] }, { cache: 'alice', title: 'OS cache', add: [] }, { cache: 'bob', title: 'OS cache', add: [] }],
      intro: `Watch one record with <b>TTL ${fmtT(T)}</b> spread through the caches and expire. The clock in the corner is simulated time.` };
  }

  function negative() {
    const bad = 'wwww.example.com.';
    const ip = Wd.web.ip4;
    const qa = D.query({ src: C.ip4, dst: R.ip4, name: bad, type: 'A' });
    const qaa = D.query({ src: R.ip4, dst: A.ip4, name: bad, type: 'A', rd: 0 });
    const raa = D.response(qaa, { aa: 1, rcode: 'NXDOMAIN', ns: [rr('example.com', 3600, 'SOA', SOA)],
      note: 'NXDOMAIN, with the zone\'s SOA record in the authority section. Negative TTL = min(SOA TTL 3600, SOA MINIMUM 300) = 300 s (RFC 2308).' });
    const ra = D.response(qa, { ra: 1, rcode: 'NXDOMAIN', ns: [rr('example.com', 300, 'SOA', SOA)] });
    const qb = D.query({ src: C2.ip4, dst: R.ip4, name: bad, type: 'A' });
    const rb = D.response(qb, { ra: 1, rcode: 'NXDOMAIN', ns: [rr('example.com', 240, 'SOA', SOA)], note: 'Served from the negative cache.' });
    const qc = D.query({ src: C.ip4, dst: R.ip4, name: bad, type: 'A' });
    const rc = D.response(qc, { ra: 1, rcode: 'NXDOMAIN', ns: [rr('example.com', 210, 'SOA', SOA)], note: 'Still NXDOMAIN, even though the record now exists on the authoritative server.' });
    const qd = D.query({ src: C.ip4, dst: R.ip4, name: bad, type: 'A' });
    const qdd = D.query({ src: R.ip4, dst: A.ip4, name: bad, type: 'A', rd: 0 });
    const rdd = D.response(qdd, { aa: 1, an: [rr(bad, 3600, 'A', ip)] });
    const rd = D.response(qd, { ra: 1, an: [rr(bad, 3600, 'A', ip)] });
    const S = [
      {
        title: 'A typo: wwww.example.com',
        focus: ['alice', 'resolver', 'auth'],
        text: '<p>Alice mistypes the hostname with four w\'s. The authoritative server replies <b>NXDOMAIN</b> ("no such name") and includes the zone\'s <b>SOA</b> record in the authority section.</p>',
        actions: [
          { lookup: 'reset' },
          { send: ['alice', 'resolver'], pkt: qa, ms: 6 },
          { send: ['resolver', 'auth'], pkt: qaa, ms: 35 },
          { send: ['auth', 'resolver'], pkt: raa, ms: 35 },
        ],
      },
      {
        title: 'Negative answers are cached too',
        focus: ['resolver', 'alice'],
        text: '<p>The resolver caches the <i>non-existence</i>. The negative TTL is the <b>smaller of the SOA record\'s TTL and its MINIMUM field</b>: min(3600, 300) = <b>300 s</b> (RFC 2308). Without negative caching, every typo and every bogus name would hit the authoritative servers.</p>',
        deep: '<p>The SOA MINIMUM field once meant "minimum TTL for the zone". RFC 2308 changed it to mean the negative-caching TTL. There is also <b>NODATA</b>: the name exists but has no records of the requested type (NOERROR with an empty answer), and it is cached the same way.</p>',
        actions: [
          { cache: 'resolver', add: [{ name: bad, type: 'A', data: 'NXDOMAIN', ttl: 300, tone: 'warn' }] },
          { send: ['resolver', 'alice'], pkt: ra, ms: 6 },
          { cache: 'alice', add: [{ name: bad, type: 'A', data: 'NXDOMAIN', ttl: 300, tone: 'warn' }] },
        ],
      },
      {
        title: 'Bob makes the same typo 60 s later',
        focus: ['bob', 'resolver'],
        text: '<p>Bob\'s query is answered from the resolver\'s negative cache with a counted-down TTL of 240 s. The authoritative server isn\'t involved at all.</p>',
        actions: [{ lookup: 'reset' }, { advance: 60 }, { send: ['bob', 'resolver'], pkt: qb, ms: 6 }, { badge: 'resolver', text: 'negative cache HIT', tone: 'warn' }, { send: ['resolver', 'bob'], pkt: rb, ms: 6 }],
      },
      {
        title: 'The admin creates the record',
        focus: ['auth'],
        text: '<p>Seeing the traffic, the admin decides to add <code>wwww.example.com A 203.0.113.10</code> as a convenience alias and bumps the zone serial. The authoritative server now answers correctly…</p>',
        actions: [{ overlay: { id: 'zone', at: 'tr', title: 'Zone updated (serial 2026092402)', html: '<pre>+ wwww  IN A  203.0.113.10</pre>' } }, { badge: 'auth', text: 'record now exists ✓', tone: 'ok', sticky: true }],
      },
      {
        title: '…but Alice still gets NXDOMAIN',
        focus: ['alice', 'resolver'],
        text: '<p>30 s later Alice tries again. The resolver still has a valid negative cache entry, so it answers <b>NXDOMAIN</b> without asking anyone. The new record stays invisible to this resolver\'s users until the negative TTL runs out.</p><p>This is why a freshly created record sometimes "doesn\'t work yet".</p>',
        actions: [
          { lookup: 'reset' }, { advance: 30 },
          { send: ['alice', 'resolver'], pkt: qc, ms: 6 }, { send: ['resolver', 'alice'], pkt: rc, ms: 6 },
          { overlay: { id: 'stale', at: 'tr', cls: 'warn', title: 'Stale negative answer', html: 'Authoritative: <b class="good">exists</b><br>Resolver cache: <b class="warnc">NXDOMAIN for another 210 s</b>' } },
        ],
      },
      {
        title: 'Negative TTL expires',
        focus: ['resolver'],
        text: '<p>After 300 s in total, the negative entry expires.</p>',
        deep: '<p>A DNSSEC-validating resolver can do even better: with <b>aggressive use of the DNSSEC-validated cache</b> (RFC 8198) it uses cached NSEC/NSEC3 ranges to synthesise NXDOMAIN for <i>other</i> non-existent names too, without asking the authoritative server. This helps absorb random-subdomain floods.</p>',
        actions: [{ advance: 215, dur: 2200 }],
      },
      {
        title: 'Now the new record resolves',
        focus: ['alice', 'resolver', 'auth'],
        text: '<p>The next query goes to the authoritative server and gets the new A record. <b>Lesson:</b> choose the SOA MINIMUM carefully. Too low and typos flood your servers; too high and new records take a long time to appear.</p>',
        actions: [
          { lookup: 'reset' },
          { send: ['alice', 'resolver'], pkt: qd, ms: 6 }, { send: ['resolver', 'auth'], pkt: qdd, ms: 35 },
          { send: ['auth', 'resolver'], pkt: rdd, ms: 35 },
          { cache: 'resolver', add: [{ name: bad, type: 'A', data: ip, ttl: 3600 }] },
          { send: ['resolver', 'alice'], pkt: rd, ms: 6 },
          { cache: 'alice', add: [{ name: bad, type: 'A', data: ip, ttl: 3600 }] },
        ],
      },
    ];
    return { nodes: nodes(), links, steps: S, hud: 'both', setup: [{ cache: 'resolver', title: 'Resolver cache', add: [] }, { cache: 'alice', title: 'OS cache', add: [] }, { cache: 'bob', title: 'OS cache', add: [] }],
      intro: 'Caching "this name does not exist" (NXDOMAIN) and why a new record can take a while to show up.' };
  }

  DV.register({
    id: 'caching',
    nav: 'Caching & TTL',
    title: 'Caching & TTL',
    icon: 'clock',
    blurb: 'Watch TTLs count down in the resolver and OS caches, see shared caches speed up other users, and learn why negative caching can hide a brand-new record.',
    intro: '<p>DNS works at Internet scale because of <b>caching</b>. Every answer carries a <b>Time To Live</b>, and every cache counts it down. Here a simulated clock lets you watch minutes and hours pass in seconds.</p>',
    options: [
      { id: 'mode', type: 'segmented', label: 'Scenario', value: 'ttl', choices: [['ttl', 'Positive caching & TTL'], ['neg', 'Negative caching (NXDOMAIN)']] },
      { id: 'ttl', type: 'segmented', label: 'Record TTL', value: '300', choices: [['60', '60 s'], ['300', '5 min'], ['3600', '1 hour']], visibleIf: (o) => o.mode === 'ttl' },
    ],
    build(o) {
      return o.mode === 'neg' ? negative(o) : positive(o);
    },
  });
})();
