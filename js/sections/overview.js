/* Section 0 — Overview: the DNS namespace and the cast of characters. */
(function () {
  'use strict';
  const DV = window.DV;

  function tree() {
    const N = [
      { id: 'root', x: 290, y: 44, t: '.', c: 'root', lvl: 'Root zone' },
      { id: 'com', x: 90, y: 140, t: 'com', c: 'tld', lvl: 'Top-level domains' },
      { id: 'org', x: 215, y: 140, t: 'org', c: 'tld' },
      { id: 'net', x: 340, y: 140, t: 'net', c: 'tld' },
      { id: 'arpa', x: 480, y: 140, t: 'arpa', c: 'tld' },
      { id: 'example', x: 90, y: 236, t: 'example', c: 'auth', lvl: 'Second-level (zone)' },
      { id: 'wiki', x: 215, y: 236, t: 'wikipedia', c: 'auth' },
      { id: 'inaddr', x: 430, y: 236, t: 'in-addr', c: 'auth' },
      { id: 'ip6', x: 530, y: 236, t: 'ip6', c: 'auth' },
      { id: 'www', x: 45, y: 330, t: 'www', c: 'web', lvl: 'Hosts' },
      { id: 'mail', x: 135, y: 330, t: 'mail', c: 'web' },
    ];
    const E = [['root', 'com'], ['root', 'org'], ['root', 'net'], ['root', 'arpa'], ['com', 'example'], ['org', 'wiki'], ['arpa', 'inaddr'], ['arpa', 'ip6'], ['example', 'www'], ['example', 'mail']];
    const by = Object.fromEntries(N.map((n) => [n.id, n]));
    const lit = new Set(['root-com', 'com-example', 'example-www']);
    const edge = ([a, b]) => {
      const A = by[a], B = by[b];
      const my = (A.y + B.y) / 2;
      return `M${A.x},${A.y + 16} C${A.x},${my} ${B.x},${my} ${B.x},${B.y - 16}`;
    };
    const path = 'M290,60 C290,92 90,92 90,124 M90,156 C90,188 90,188 90,220 M90,252 C90,284 45,284 45,314';
    return `<svg class="tree-svg" viewBox="0 0 700 400" role="img" aria-label="The DNS namespace tree: root, top-level domains, second-level domains and hosts">
      ${E.map((e) => `<path class="edge" d="${edge(e)}"/>`).join('')}
      ${E.filter((e) => lit.has(e.join('-'))).map((e) => `<path class="edge lit" d="${edge(e)}"/>`).join('')}
      ${N.map((n) => `<g class="tn"><circle cx="${n.x}" cy="${n.y}" r="16" fill="var(--card)" stroke="var(--t-${n.c})"/>
        <text x="${n.x}" y="${n.y + (n.id === 'root' ? 5 : 34)}" text-anchor="middle" ${n.id === 'root' ? 'style="font-size:20px"' : ''}>${n.t}</text></g>`).join('')}
      ${N.filter((n) => n.lvl).map((n) => `<text x="692" y="${n.y + 4}" text-anchor="end" style="font:600 10px var(--sans);letter-spacing:.08em;fill:var(--faint)">${n.lvl.toUpperCase()}</text>`).join('')}
      <circle class="pulse" r="5"><animateMotion dur="6s" repeatCount="indefinite" keyPoints="0;1;1" keyTimes="0;.5;1" calcMode="linear" path="${path}"/></circle>
      <text x="20" y="392" style="font:500 12px var(--mono);fill:var(--accent)">www.example.com. = www → example → com → . (root)</text>
    </svg>`;
  }

  DV.register({
    id: 'overview',
    nav: 'Overview',
    title: 'Overview',
    icon: 'overview',
    render(host) {
      const actors = [
        ['client', 'laptop', 'Stub resolver', 'The small resolver built into your OS (reached through <code>getaddrinfo()</code>). It asks one question and expects a complete answer.'],
        ['resolver', 'resolver', 'Recursive resolver', 'Your ISP, company or a public service (for example 1.1.1.1 or 8.8.8.8). It does the legwork: it follows referrals, caches results and validates DNSSEC.'],
        ['root', 'root', 'Root servers', '13 named identities (a–m.root-servers.net) served by more than 1,900 anycast instances. They only know who runs each TLD.'],
        ['tld', 'tld', 'TLD servers', 'Run by registries (for example Verisign for .com). They know which name servers are authoritative for each registered domain.'],
        ['auth', 'auth', 'Authoritative servers', 'Hold the actual zone data (A, AAAA, MX, TXT…) and sign it with DNSSEC. They give the final answer, with AA=1.'],
      ];
      const lessons = DV.sections.filter((s) => s.id !== 'overview');
      host.innerHTML = `
        <section class="hero">
          <div>
            <div class="eyebrow">${DV.icon('overview')} Interactive guide</div>
            <h1>How a <em>name</em> becomes a <em>connection</em></h1>
            <p>Every time you open a website, send an email or join a call, your device first asks the Domain Name System to turn a name into an address. These animated lessons follow each packet through that process, from your laptop to the root servers and back, and on to the TCP, TLS and SMTP connections that use the answer.</p>
            <p>Every DNS packet here is a real message encoded in RFC 1035 wire format. Click any packet to decode it field by field and inspect its bytes.</p>
            <div class="cta">
              <a class="btn primary" href="#resolution">${DV.icon('play')} Start: full resolution</a>
              <a class="btn" href="#records">${DV.icon('records')} Browse record types</a>
            </div>
          </div>
          <div class="card tree-card">${tree()}</div>
        </section>

        <h2 class="sec-title">The cast of characters</h2>
        <div class="actors">${actors
          .map(([t, ic, h, p]) => `<div class="card actor" style="--c:var(--t-${t})"><h3>${DV.icon(ic)} ${h}</h3><p>${p}</p></div>`)
          .join('')}</div>

        <h2 class="sec-title">Lessons</h2>
        <div class="lesson-grid">${lessons
          .map((s, i) => `<a class="card lesson-card" href="#${s.id}"><div class="lc-top">${DV.icon(s.icon)}<span class="lc-n">${String(i + 1).padStart(2, '0')}</span></div><h3>${s.title}</h3><p>${s.blurb || ''}</p></a>`)
          .join('')}</div>

        <h2 class="sec-title">How to use the visualizer</h2>
        <div class="howto">
          <div class="card"><b>▶ Play or step through</b>Use Play to run a lesson hands-free, or use <kbd>←</kbd> <kbd>→</kbd> to go one step at a time. You can also click a step in the Steps tab to jump straight to it.</div>
          <div class="card"><b>🔍 Inspect packets</b>Click a packet while it's moving, or pick one from the Packets list, to see its IP/UDP headers, DNS flags and records, and a hex dump you can hover over.</div>
          <div class="card"><b>⚙ Change the scenario</b>Each lesson has options such as cache hit vs miss, A vs AAAA, a tampered DNSSEC answer, or DoH vs Do53. Change one and see how the whole flow changes.</div>
          <div class="card"><b>🧠 Under the hood</b>Open <i>Under the hood</i> below the narration for RFC references, edge cases and details used in real operations.</div>
        </div>
        <div class="legend-row" style="margin-top:14px">
          <span class="tone-q"><i></i>DNS query</span><span class="tone-r"><i></i>Answer</span><span class="tone-ref"><i></i>Referral</span>
          <span class="tone-warn"><i></i>NXDOMAIN / negative</span><span class="tone-bad"><i></i>Error / forged</span><span class="tone-enc"><i></i>Encrypted</span>
          <span class="tone-gen"><i></i>TCP / other protocols</span>
        </div>`;
    },
  });
})();
