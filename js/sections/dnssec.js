/* Section 6 — DNSSEC: the chain of trust from the root trust anchor down to a signed answer. */
(function () {
  'use strict';
  const DV = window.DV;
  const D = DV.dns, Wd = DV.world;
  const rr = D.rr;
  const C = Wd.client, R = Wd.resolver, RT = Wd.root, COM = Wd.com, A = Wd.auth;
  const KR = Wd.keys.root, KC = Wd.keys.com, KE = Wd.keys.ex;
  const SOA = 'ns1.example.com. hostmaster.example.com. 2026092401 7200 3600 1209600 300';

  function b32hex(bytes) {
    const alpha = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
    let bits = 0, val = 0, out = '';
    for (const b of bytes) {
      val = (val << 8) | b; bits += 8;
      while (bits >= 5) { out += alpha[(val >> (bits - 5)) & 31]; bits -= 5; }
    }
    if (bits) out += alpha[(val << (5 - bits)) & 31];
    return out;
  }
  const h3 = (s) => b32hex(D.noise('nsec3' + s, 20));

  const panel = `<div class="chain">
    <div class="cbox zone-ta" data-k="ta"><b>Trust anchor</b><small>Root KSK ${KR.ksk.tag}, configured in the resolver (RFC 5011 keeps it updated)</small></div>
    <div class="clink">must match</div>
    <div class="cbox zone-root" data-k="rootkeys"><b>. DNSKEY</b><small>Root key set (KSK + ZSK), signed by KSK ${KR.ksk.tag}</small></div>
    <div class="clink">root ZSK ${KR.zsk.tag} signs</div>
    <div class="cbox zone-root" data-k="dscom"><b>com. DS</b><small>Hash of the .com KSK, published in the root zone</small></div>
    <div class="clink">hash must match</div>
    <div class="cbox zone-tld" data-k="comkeys"><b>com. DNSKEY</b><small>.com key set, signed by .com KSK ${KC.ksk.tag}</small></div>
    <div class="clink">.com ZSK ${KC.zsk.tag} signs</div>
    <div class="cbox zone-tld" data-k="dsex"><b>example.com. DS</b><small>Hash of the example.com KSK, published in .com</small></div>
    <div class="clink">hash must match</div>
    <div class="cbox zone-auth" data-k="exkeys"><b>example.com. DNSKEY</b><small>Key set, signed by KSK ${KE.ksk.tag}</small></div>
    <div class="clink">ZSK ${KE.zsk.tag} signs</div>
    <div class="cbox zone-auth" data-k="ans"><b>www.example.com. A</b><small>203.0.113.10 + RRSIG</small></div>
  </div>
  <div class="pnote">Each box turns <span class="good">✓</span> when its signature and hash checks pass, <span class="badc">✗</span> when they fail, or <span class="warnc">—</span> when the zone is provably unsigned (insecure).</div>`;

  DV.register({
    id: 'dnssec',
    nav: 'DNSSEC',
    title: 'DNSSEC: the chain of trust',
    icon: 'shield',
    blurb: 'Watch a validating resolver walk DS → DNSKEY → RRSIG from the root trust anchor down to the answer, then see what happens with tampered, non-existent and unsigned names.',
    intro: '<p>Plain DNS has no way to tell whether an answer is genuine. <b>DNSSEC</b> adds digital signatures: every zone signs its records, and each parent vouches for its child\'s key with a <b>DS</b> record. A validating resolver follows this <b>chain of trust</b> from one key it already trusts, the root KSK.</p>',
    options: [
      { id: 'mode', type: 'segmented', label: 'Scenario', value: 'valid', choices: [['valid', 'Valid signed answer'], ['tamper', 'Tampered answer'], ['nx', 'Signed NXDOMAIN (NSEC3)'], ['insecure', 'Unsigned zone']] },
    ],
    build(o) {
      const m = o.mode;
      const qname = m === 'nx' ? 'nope.example.com' : 'www.example.com';
      const nodes = [
        { id: 'client', x: 95, y: 290, icon: 'laptop', tier: 'client', label: 'Stub resolver', sub: C.ip4 },
        { id: 'resolver', x: 380, y: 290, icon: 'resolver', tier: 'resolver', label: 'Validating resolver', sub: R.ip4 },
        { id: 'root', x: 810, y: 95, icon: 'root', tier: 'root', label: 'Root server', sub: RT.ip4 },
        { id: 'tld', x: 860, y: 290, icon: 'tld', tier: 'tld', label: '.com TLD server', sub: COM.ip4 },
        { id: 'auth', x: 810, y: 480, icon: 'auth', tier: 'auth', label: 'ns1.example.com', sub: m === 'insecure' ? `${A.ip4} (unsigned)` : `${A.ip4} (signed)` },
        { id: 'attacker', x: 560, y: 470, icon: 'attacker', tier: 'evil', label: 'On-path attacker', sub: 'rewrites packets', hidden: m !== 'tamper', size: 'sm' },
      ];
      const links = [['client', 'resolver'], ['resolver', 'root'], ['resolver', 'tld'], ['resolver', 'auth'], ['auth', 'attacker'], ['attacker', 'resolver']];

      const q0 = D.query({ src: C.ip4, dst: R.ip4, name: qname, type: 'A', ad: 1, note: 'The stub sets AD=1 in the query to say "tell me whether you validated this" (RFC 6840).' });
      // root
      const qR = D.query({ src: R.ip4, dst: RT.ip4, name: qname, type: 'A', rd: 0, do: true, note: 'DO=1 (DNSSEC OK): please include DNSSEC records.' });
      const rR = D.response(qR, {
        ns: [rr('com', 172800, 'NS', COM.name), rr('com', 86400, 'DS', `${KC.ksk.tag} 13 2 ${KC.ds}`), rr('com', 86400, 'RRSIG', D.rrsig('DS', 8, 1, 86400, KR.zsk.tag, '.'))],
        ar: [rr(COM.name, 172800, 'A', COM.ip4)],
        note: 'Referral plus the signed DS for com. The NS records in a referral are NOT signed (the child is authoritative for them), but the DS is.' });
      const qRK = D.query({ src: R.ip4, dst: RT.ip4, name: '.', type: 'DNSKEY', rd: 0, do: true });
      const rRK = D.response(qRK, { aa: 1, an: [rr('.', 172800, 'DNSKEY', D.dnskey(KR.ksk, true)), rr('.', 172800, 'DNSKEY', D.dnskey(KR.zsk, false)), rr('.', 172800, 'RRSIG', D.rrsig('DNSKEY', 8, 0, 172800, KR.ksk.tag, '.'))],
        note: 'The root key set (algorithm 8 = RSA/SHA-256), signed by the KSK. The KSK must equal the configured trust anchor.' });
      // com
      const qC = D.query({ src: R.ip4, dst: COM.ip4, name: qname, type: 'A', rd: 0, do: true });
      const noDS = [
        rr(h3('example.com') + '.com', 86400, 'NSEC3', `1 1 0 - ${h3('example.com+1')} NS`),
        rr(h3('example.com') + '.com', 86400, 'RRSIG', D.rrsig('NSEC3', 13, 2, 86400, KC.zsk.tag, 'com')),
      ];
      const rC = D.response(qC, {
        ns: m === 'insecure'
          ? [rr('example.com', 172800, 'NS', A.name), ...noDS]
          : [rr('example.com', 172800, 'NS', A.name), rr('example.com', 86400, 'DS', `${KE.ksk.tag} 13 2 ${KE.ds}`), rr('example.com', 86400, 'RRSIG', D.rrsig('DS', 13, 2, 86400, KC.zsk.tag, 'com'))],
        ar: [rr(A.name, 172800, 'A', A.ip4)],
        note: m === 'insecure' ? 'No DS record. Instead a signed NSEC3 proves that example.com has no DS, so the delegation is provably INSECURE.' : 'Referral plus the signed DS for example.com.' });
      const qCK = D.query({ src: R.ip4, dst: COM.ip4, name: 'com', type: 'DNSKEY', rd: 0, do: true });
      const rCK = D.response(qCK, { aa: 1, an: [rr('com', 86400, 'DNSKEY', D.dnskey(KC.ksk, true)), rr('com', 86400, 'DNSKEY', D.dnskey(KC.zsk, false)), rr('com', 86400, 'RRSIG', D.rrsig('DNSKEY', 13, 1, 86400, KC.ksk.tag, 'com'))] });
      // example.com
      const qE = D.query({ src: R.ip4, dst: A.ip4, name: qname, type: 'A', rd: 0, do: true });
      const aRec = rr('www.example.com', 3600, 'A', Wd.web.ip4);
      const aSig = rr('www.example.com', 3600, 'RRSIG', D.rrsig('A', 13, 3, 3600, KE.zsk.tag, 'example.com'));
      const nx = [
        rr('example.com', 300, 'SOA', SOA), rr('example.com', 300, 'RRSIG', D.rrsig('SOA', 13, 2, 300, KE.zsk.tag, 'example.com')),
        rr(h3('ex-apex') + '.example.com', 300, 'NSEC3', `1 0 0 - ${h3('ex-apex+1')} A NS SOA MX TXT RRSIG DNSKEY NSEC3PARAM`),
        rr(h3('ex-apex') + '.example.com', 300, 'RRSIG', D.rrsig('NSEC3', 13, 3, 300, KE.zsk.tag, 'example.com')),
        rr(h3('ex-cover') + '.example.com', 300, 'NSEC3', `1 0 0 - ${h3('ex-cover+1')} A RRSIG`),
        rr(h3('ex-cover') + '.example.com', 300, 'RRSIG', D.rrsig('NSEC3', 13, 3, 300, KE.zsk.tag, 'example.com')),
      ];
      const rE = m === 'nx'
        ? D.response(qE, { aa: 1, rcode: 'NXDOMAIN', ns: nx, note: 'NXDOMAIN proven by NSEC3: one record matches the closest encloser (example.com), and another covers the hash of nope.example.com (and of the wildcard). All of them are signed.' })
        : m === 'insecure'
          ? D.response(qE, { aa: 1, an: [aRec], note: 'Unsigned zone: no RRSIG, even though DO=1 was set.' })
          : D.response(qE, { aa: 1, an: [aRec, aSig], note: 'The A record plus its RRSIG, made with ZSK ' + KE.zsk.tag + '.' });
      const forged = D.response(qE, { aa: 1, an: [rr('www.example.com', 3600, 'A', Wd.attacker.ip4), aSig], forged: true, note: 'The attacker changed the A record to its own server but cannot produce a matching signature. It can only copy the original RRSIG, which no longer matches the data.' });
      const qEK = D.query({ src: R.ip4, dst: A.ip4, name: 'example.com', type: 'DNSKEY', rd: 0, do: true });
      const rEK = D.response(qEK, { aa: 1, an: [rr('example.com', 3600, 'DNSKEY', D.dnskey(KE.ksk, true)), rr('example.com', 3600, 'DNSKEY', D.dnskey(KE.zsk, false)), rr('example.com', 3600, 'RRSIG', D.rrsig('DNSKEY', 13, 2, 3600, KE.ksk.tag, 'example.com'))] });
      // final answer
      const rFinal = m === 'tamper'
        ? D.response(q0, { ra: 1, rcode: 'SERVFAIL', ede: { code: 6, text: 'DNSSEC Bogus' }, note: 'Validation failed, so the resolver returns SERVFAIL rather than the forged address. Extended DNS Error 6 (RFC 8914) says why.' })
        : m === 'nx'
          ? D.response(q0, { ra: 1, ad: 1, rcode: 'NXDOMAIN', ns: nx.slice(0, 2), note: 'AD=1: the non-existence has been cryptographically proven.' })
          : m === 'insecure'
            ? D.response(q0, { ra: 1, ad: 0, an: [aRec], note: 'AD=0: the answer is INSECURE (provably unsigned). It is returned, but without any authenticity guarantee.' })
            : D.response(q0, { ra: 1, ad: 1, an: [aRec, aSig], note: 'AD=1 (Authenticated Data): every link in the chain from the root trust anchor to this record verified.' });

      const S = [];
      S.push({
        title: 'A validating resolver and its trust anchor',
        focus: ['client', 'resolver'],
        text: `<p>The stub asks for <code>${qname}</code>. The resolver validates DNSSEC and holds a <b>trust anchor</b>: a copy of the root zone's Key Signing Key (KSK ${KR.ksk.tag}). This is the only key it trusts before it starts. Every other key has to be proven from here.</p>`,
        deep: '<p>The root KSK was last rolled in 2018 (KSK-2017, tag 20326); a successor (KSK-2024) is being introduced. Resolvers follow rollovers automatically with RFC 5011, or update the anchor with a software release.</p>',
        actions: [{ send: ['client', 'resolver'], pkt: q0 }, { mark: { ta: 'ok' } }, { badge: 'resolver', text: `🔑 trust anchor: root KSK ${KR.ksk.tag}`, tone: 'info', sticky: true }],
      });
      S.push({
        title: 'Root referral with a signed DS for .com',
        focus: ['resolver', 'root'],
        text: '<p>The resolver queries with <b>DO=1</b>. The root\'s referral includes the <b>DS</b> record for <code>com.</code>, a hash of .com\'s KSK, together with an <b>RRSIG</b> made with the root\'s ZSK.</p>',
        actions: [{ send: ['resolver', 'root'], pkt: qR }, { send: ['root', 'resolver'], pkt: rR }, { mark: { dscom: 'checking' } }],
      });
      S.push({
        title: 'Fetch and verify the root DNSKEYs',
        focus: ['resolver', 'root'],
        text: '<p>To check that RRSIG, the resolver needs the root\'s public keys, so it fetches <code>. DNSKEY</code>. Then:</p><ol><li>Does the KSK in this set match the <b>trust anchor</b>? <span class="good">✓</span></li><li>Does the KSK\'s signature over the DNSKEY set verify? <span class="good">✓</span> Now the root ZSK is trusted.</li><li>Does the ZSK\'s signature over <code>com. DS</code> verify? <span class="good">✓</span></li></ol>',
        deep: '<p>The key tag in each RRSIG (a 16-bit checksum of the key) tells the validator which DNSKEY to try. Key tags can collide, so validators must try every key with a matching tag.</p>',
        actions: [{ send: ['resolver', 'root'], pkt: qRK }, { send: ['root', 'resolver'], pkt: rRK }, { mark: { rootkeys: 'checking' } }, { wait: 500 }, { mark: { rootkeys: 'ok' } }, { wait: 400 }, { mark: { dscom: 'ok' } }],
      });
      S.push({
        title: m === 'insecure' ? '.com referral: no DS for example.com' : '.com referral with a signed DS for example.com',
        focus: ['resolver', 'tld'],
        text: m === 'insecure'
          ? '<p>The .com referral contains <b>no DS</b> for example.com. Instead there is a signed <b>NSEC3</b> record proving that no DS exists. The owner has not enabled DNSSEC, and the proof itself is signed, so an attacker can\'t fake "unsigned" to downgrade a signed domain.</p>'
          : '<p>Same pattern one level down: a referral to example.com\'s servers, plus the <b>DS</b> for example.com signed by the .com ZSK.</p>',
        actions: [{ send: ['resolver', 'tld'], pkt: qC }, { send: ['tld', 'resolver'], pkt: rC }, { mark: { dsex: 'checking' } }],
      });
      S.push({
        title: 'Verify the .com keys against the root\'s DS',
        focus: ['resolver', 'tld'],
        text: `<p>The resolver fetches <code>com. DNSKEY</code> and hashes the .com KSK. The hash <b>matches the DS</b> the root signed <span class="good">✓</span>. The .com key set's signature verifies <span class="good">✓</span>. Then the .com ZSK is used to check the ${m === 'insecure' ? 'NSEC3 no-DS proof' : 'example.com DS'} <span class="good">✓</span>.</p>`,
        actions: [
          { send: ['resolver', 'tld'], pkt: qCK }, { send: ['tld', 'resolver'], pkt: rCK }, { mark: { comkeys: 'checking' } }, { wait: 500 }, { mark: { comkeys: 'ok' } }, { wait: 400 },
          m === 'insecure'
            ? { seq: [{ panelHtml: { dsex: '<b>example.com. DS</b><small>None. The signed NSEC3 proves there is no DS, so the delegation is <b>insecure</b></small>' } }, { mark: { dsex: 'insecure', exkeys: 'insecure' } }] }
            : { mark: { dsex: 'ok' } },
        ],
      });
      if (m === 'tamper') {
        S.push({
          title: 'An attacker rewrites the answer in transit',
          focus: ['auth', 'attacker', 'resolver'],
          text: '<p>The genuine signed answer leaves ns1.example.com, but an <b>on-path attacker</b> (a compromised router, rogue Wi-Fi, BGP hijack…) changes the A record to its own server, <code>198.51.100.66</code>. It can\'t re-sign the data without example.com\'s private key, so it leaves the old RRSIG in place.</p>',
          actions: [
            { show: ['attacker'] }, { send: ['resolver', 'auth'], pkt: qE },
            { send: ['auth', 'attacker'], pkt: rE },
            { badge: 'attacker', text: 'A → 198.51.100.66 😈', tone: 'bad' },
            { send: ['attacker', 'resolver'], pkt: forged, tone: 'bad' },
            { mark: { ans: 'checking' } },
            { panelHtml: { ans: '<b>www.example.com. A</b><small>198.51.100.66 (modified) + original RRSIG</small>' } },
          ],
        });
      } else {
        S.push({
          title: m === 'nx' ? 'Authoritative: NXDOMAIN plus NSEC3 proof' : m === 'insecure' ? 'Authoritative: an unsigned answer' : 'Authoritative: A record plus RRSIG',
          focus: ['resolver', 'auth'],
          text: m === 'nx'
            ? '<p><code>nope.example.com</code> doesn\'t exist. The server returns NXDOMAIN with signed <b>NSEC3</b> records: one matches the closest existing ancestor (example.com), and one <i>covers</i> the hash of the missing name, proving nothing exists there. Click the packet to see them.</p>'
            : m === 'insecure'
              ? '<p>The answer has no RRSIG because the zone is unsigned. The resolver already knows from the NSEC3 proof that this is expected, so it doesn\'t treat the missing signature as an attack.</p>'
              : '<p>The answer carries the A record <b>and</b> its RRSIG, made with example.com\'s ZSK.</p>',
          actions: [
            { send: ['resolver', 'auth'], pkt: qE }, { send: ['auth', 'resolver'], pkt: rE },
            m === 'insecure' ? { mark: { ans: 'insecure' } } : { mark: { ans: 'checking' } },
            ...(m === 'nx' ? [{ panelHtml: { ans: '<b>nope.example.com.</b><small>NXDOMAIN, with signed NSEC3 denial of existence</small>' } }] : []),
          ],
        });
      }
      if (m !== 'insecure') {
        S.push({
          title: m === 'tamper' ? 'Verification FAILS: bogus!' : 'Verify example.com keys and the answer',
          focus: ['resolver', 'auth'],
          text: m === 'tamper'
            ? '<p>The example.com keys check out against the DS <span class="good">✓</span>. But when the resolver verifies the RRSIG over the A record with the ZSK, the signature <b>does not match</b> the modified data <span class="badc">✗</span>. The answer is <b>bogus</b> and will not be cached or returned.</p>'
            : '<p>The resolver fetches <code>example.com DNSKEY</code>, checks the KSK against the DS from .com <span class="good">✓</span> and the key set\'s signature <span class="good">✓</span>, then verifies the answer\'s RRSIG with the ZSK <span class="good">✓</span>. <b>The chain is complete.</b></p>',
          deep: '<p>For each signature the validator also checks the inception and expiration times, the signer name, the labels count, and that the algorithm is one it supports. A zone signed only with algorithms the resolver doesn\'t implement is treated as insecure, not bogus.</p>',
          actions: [
            { send: ['resolver', 'auth'], pkt: qEK }, { send: ['auth', 'resolver'], pkt: rEK }, { mark: { exkeys: 'checking' } }, { wait: 500 }, { mark: { exkeys: 'ok' } }, { wait: 400 },
            m === 'tamper'
              ? { seq: [{ mark: { ans: 'bad' } }, { badge: 'resolver', text: '✗ RRSIG mismatch → BOGUS', tone: 'bad' }, { overlay: { id: 'v', at: 'tl', cls: 'bad', title: 'verify(RRSIG, A RRset, ZSK)', html: 'signed data: <code>www A 203.0.113.10</code><br>received: <code>www A 198.51.100.66</code><br><b class="badc">signature invalid</b>' } }] }
              : { seq: [{ mark: { ans: 'ok' } }, { overlay: { id: 'v', at: 'tl', cls: 'ok', title: 'Chain of trust verified', html: 'trust anchor → . → com → example.com → answer <span class="good">✓</span>' } }] },
          ],
        });
      }
      S.push({
        title: m === 'tamper' ? 'Client gets SERVFAIL, not the attacker\'s IP' : m === 'insecure' ? 'Answer returned with AD=0 (insecure)' : 'Answer returned with AD=1',
        focus: ['resolver', 'client'],
        text: m === 'tamper'
          ? '<p>The resolver returns <b>SERVFAIL</b> with Extended DNS Error 6 "DNSSEC Bogus". The user sees an error page instead of silently landing on the attacker\'s server. DNSSEC <b>fails closed</b>.</p><p>For debugging, <code>dig +cd</code> (Checking Disabled) asks the resolver to return the data without validating it.</p>'
          : m === 'insecure'
            ? '<p>The answer is delivered with <b>AD=0</b>. It is <i>insecure</i> (provably unsigned), not <i>bogus</i>. There is no authenticity guarantee: this is how most of the Internet\'s names still resolve.</p>'
            : '<p>The stub receives the answer with <b>AD=1</b> (Authenticated Data). Note that the stub is trusting its resolver to have validated honestly, so the link between them should be protected (DoT/DoH) or the device should validate for itself.</p>',
        deep: '<p>DNSSEC provides <b>data origin authentication and integrity</b>. It does <b>not</b> encrypt anything (see the Privacy lesson). Typical causes of real-world bogus answers are expired signatures and DS/KSK mismatches after a botched rollover.</p>',
        actions: [
          { send: ['resolver', 'client'], pkt: rFinal },
          m === 'tamper' ? { badge: 'client', text: 'SERVFAIL: page won\'t load', tone: 'bad' } : m === 'insecure' ? { badge: 'client', text: 'AD=0 insecure', tone: 'warn' } : { badge: 'client', text: 'AD=1 ✓ authenticated', tone: 'ok' },
          m === 'tamper' ? { cls: ['resolver', 'shielded'] } : m === 'insecure' ? {} : { cls: ['client', 'secure'] },
        ],
      });

      return { nodes, links, steps: S, panel: { title: `${DV.icon('shield')} Chain of trust`, html: panel },
        intro: { valid: 'A fully signed lookup, validated from the root trust anchor down.', tamper: 'The same lookup, but an attacker modifies the answer on the way back.', nx: 'Proving that <code>nope.example.com</code> does not exist, using signed NSEC3 records.', insecure: 'A lookup for a zone whose owner never enabled DNSSEC.' }[m] + ' Watch the chain-of-trust panel on the right.' };
    },
  });
})();
