/* net.js — builders for the non-DNS packets (TCP, TLS, HTTP, SMTP, QUIC) that follow a lookup. */
(function () {
  'use strict';
  const DV = (window.DV = window.DV || {});
  const D = DV.dns;
  const v = (ip) => (ip.includes(':') ? 6 : 4);

  DV.net = {
    tcp(flags, src, dst, sport, dport, extra) {
      return D.generic(Object.assign({
        src, dst, v: v(src), proto: 'TCP', sport, dport, tcpFlags: flags,
        summary: `TCP ${flags} ${sport} → ${dport}`, label: flags, size: 0,
      }, extra || {}));
    },
    /** TLS handshake record (plaintext parts visible). fields: [[k,v]] */
    tls(name, src, dst, sport, dport, fields, extra) {
      return D.generic(Object.assign({
        src, dst, v: v(src), proto: 'TCP', sport, dport, summary: `TLS ${name}`, label: name,
        layers: [{ name: `Transport Layer Security — ${name}`, fields }],
      }, extra || {}));
    },
    /** An encrypted application-data packet wrapping an inner (decrypted) view. */
    appData(innerSummary, src, dst, sport, dport, innerFields, extra) {
      const inner = D.generic({ summary: innerSummary, layers: [{ name: extra && extra.innerName ? extra.innerName : 'Decrypted application data', fields: innerFields }] });
      return D.generic(Object.assign({
        src, dst, v: v(src), proto: extra && extra.proto ? extra.proto : 'TCP', sport, dport, enc: true, inner,
        summary: extra && extra.outerSummary ? extra.outerSummary : 'TLS Application Data', label: innerSummary,
      }, extra || {}));
    },
    smtp(line, src, dst, sport, dport, extra) {
      return D.generic(Object.assign({
        src, dst, v: v(src), proto: 'TCP', sport, dport, summary: `SMTP ${line}`, label: line,
        layers: [{ name: 'Simple Mail Transfer Protocol', fields: [['Line', `<span class="mono">${DV.esc(line)}</span>`]] }],
      }, extra || {}));
    },
  };
})();
