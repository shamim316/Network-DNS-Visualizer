# DNS Visualizer

An animated, step-by-step visual learning tool for network engineering students that shows how DNS works on the Internet: from a browser's first cache check, through the root → TLD → authoritative hierarchy, to the TCP/TLS/HTTP, SMTP and SIP connections that use the answer.

Every DNS packet in the animations is a real message encoded in RFC 1035 wire format, with name compression. Click any packet to open a Wireshark-style inspector with IP/UDP/TCP layers, the DNS header flag bits, each record section, and a hex dump you can hover over.

## Lessons

| # | Lesson | Scenarios you can switch between |
|---|--------|----------------------------------|
| 0 | **Overview** | DNS namespace tree, the actors, how to use the tool |
| 1 | **Full recursive resolution** | Custom domain · A / AAAA · cold, partly warm, resolver-hit or browser-hit cache · QNAME minimisation · truncated answer → TCP fallback |
| 2 | **Using the answer** | Web page (TCP → TLS 1.3 with SNI → HTTP/2, plus a CDN sub-resource via a CNAME chain) · HTTP/3 via the HTTPS RR + QUIC · Email (MX, failover when the primary MX is down, PTR/FCrDNS, SPF, DKIM, DMARC) · VoIP service discovery via SRV |
| 3 | **Caching & TTL** | TTL countdown across OS and resolver caches, shared-cache hits, expiry and refresh (60 s / 5 min / 1 h) · Negative caching (NXDOMAIN and the SOA MINIMUM) |
| 4 | **Record types** | A, AAAA, CNAME, MX, NS, SOA (+ NOTIFY/AXFR), TXT, PTR, SRV, CAA, HTTPS/SVCB, DNSKEY, DS, RRSIG, NSEC/NSEC3, with the matching zone-file lines highlighted |
| 5 | **IPv4 vs IPv6** | Dual-stack A + AAAA lookups and RFC 6724 address selection · IPv6-only with DNS64/NAT64 · Reverse DNS: in-addr.arpa vs ip6.arpa (nibbles) |
| 6 | **DNSSEC** | Live chain-of-trust panel: valid answer · tampered answer (bogus → SERVFAIL + EDE) · signed NXDOMAIN (NSEC3) · unsigned (insecure) zone |
| 7 | **Privacy: DoT & DoH** | Do53 vs DoT vs DoH, with an "observer" panel showing what leaks; TLS SNI vs Encrypted Client Hello |
| 8 | **Attacks & defences** | Classic and Kaminsky cache poisoning against no defence, source-port randomisation, or DNSSEC · reflection/amplification DDoS vs BCP 38 + closed resolvers + RRL |

Controls: **Space** play/pause · **← / →** previous/next step · **R** restart. Each step has an **Under the hood** section with RFC references and operational detail.

## Running it

It's a static site with no build step and no dependencies.

- **Locally:** open `index.html` in a browser, or serve the folder (`python3 -m http.server`) and browse to `http://localhost:8000`.
- **GitHub Pages:** the workflow in `.github/workflows/pages.yml` deploys the repository root on every push to `main`. In the repository settings go to **Pages → Build and deployment → Source** and choose **GitHub Actions**.

## Project layout

```
index.html              page shell
css/style.css           dark "network ops" theme + light theme
js/dns.js               DNS message model, RFC 1035 wire encoder, packet builders, shared addresses
js/net.js               TCP / TLS / HTTP / SMTP / QUIC packet builders
js/engine.js            lesson player: stage, nodes, animated packets, caches, overlays, step control
js/inspector.js         packet inspector and hex dump
js/app.js               navigation, routing and theme
js/sections/*.js        one file per lesson
```

### Adding a lesson

Call `DV.register({ id, nav, title, icon, blurb, intro, options, build(opts) })`. `build` returns `{ nodes, links, steps, … }`. Each step is `{ title, text, deep, focus, actions }`, and actions are declarative (`send`, `par`, `badge`, `cache`, `advance`, `link`, `overlay`, `hl`, `mark`, …). That's what lets the player jump to any step by replaying the earlier ones instantly. See `js/engine.js` for the full list and `js/sections/resolution.js` for a complete example.

## Notes on accuracy

Addresses come from the documentation ranges (RFC 5737 `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, and RFC 3849 `2001:db8::/32`). The exceptions are the real `a.root-servers.net` and `a.gtld-servers.net` addresses and the real root KSK key tag (20326). Other key material, signatures and hashes are illustrative. Referrals are trimmed to a few NS records for readability, and each such packet says so in its note.
