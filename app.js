/* app.js — pure logic for the V2Ray subscription viewer.
   No DOM access here, so this file can be unit-tested in Node. */

'use strict';

/* Decode a base64 (standard or URL-safe) string into UTF-8 text. */
function b64ToText(b64) {
  let s = String(b64 || '').trim().replace(/-/g, '+').replace(/_/g, '/');
  s = s.replace(/\s+/g, '');
  while (s.length % 4 !== 0) s += '=';
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

/* Best-effort percent-decoding (handles Persian remarks etc.). */
function safeDecode(s) {
  s = String(s || '');
  try {
    // '+' in fragments is a literal plus, not a space — only decode %XX.
    return decodeURIComponent(s);
  } catch (e) {
    try {
      return decodeURIComponent(s.replace(/%(?![0-9a-fA-F]{2})/g, '%25'));
    } catch (e2) {
      return s;
    }
  }
}

function getParam(query, key) {
  if (!query) return '';
  try {
    return new URLSearchParams(query).get(key) || '';
  } catch (e) {
    const m = query.match(new RegExp('[?&]' + key + '=([^&]*)'));
    return m ? m[1] : '';
  }
}

/*
 * Take the raw subscription response (plain text of config URIs, or a
 * base64 blob of them) and return an array of config URI strings.
 */
function extractConfigLines(raw) {
  let text = String(raw || '').trim();
  if (!text) return [];
  const looksLikeUris = /^[a-z0-9+.-]+:\/\//im.test(text);
  if (!looksLikeUris) {
    try {
      const decoded = b64ToText(text);
      if (/^[a-z0-9+.-]+:\/\//im.test(decoded)) text = decoded;
    } catch (e) {
      /* not base64 — keep raw text */
    }
  }
  return text
    .split(/\r?\n/)
    .map(function (l) { return l.trim(); })
    .filter(function (l) { return /^[a-z0-9+.-]+:\/\//i.test(l); });
}

var PROTO_LABELS = {
  vmess: 'VMess',
  vless: 'VLESS',
  trojan: 'Trojan',
  ss: 'Shadowsocks',
  ssr: 'SSR',
  hy2: 'Hysteria2',
  hysteria2: 'Hysteria2',
  hysteria: 'Hysteria',
  tuic: 'TUIC',
  wireguard: 'WireGuard',
  socks: 'SOCKS',
  socks5: 'SOCKS5',
  http: 'HTTP'
};

function protoLabel(p) {
  return PROTO_LABELS[p] || p.toUpperCase();
}

/* Parse one config URI into { proto, name, host, port, uri }. */
function parseConfigLine(uri) {
  uri = String(uri || '').trim();
  const m = uri.match(/^([a-z0-9+.-]+):\/\/(.*)$/is);
  if (!m) return null;
  const proto = m[1].toLowerCase();
  const body = m[2].trim();
  let name = '';
  let host = '';
  let port = '';

  const takeName = function (hash) {
    return safeDecode(String(hash || '').replace(/^#/, ''));
  };

  try {
    if (proto === 'vmess') {
      // vmess://base64(json)#optional
      const payload = body.split('#')[0].split('?')[0];
      const j = JSON.parse(b64ToText(payload));
      name = String(j.ps || j.add || '');
      host = String(j.add || '');
      port = String(j.port || j.net || '');
      if (port && !/^\d+$/.test(port)) port = '';
    } else if (proto === 'ssr') {
      // ssr://base64(host:port:protocol:method:obfs:b64pass/?params)
      const decoded = b64ToText(body);
      const qi = decoded.indexOf('/?');
      const head = qi === -1 ? decoded : decoded.slice(0, qi);
      const query = qi === -1 ? '' : decoded.slice(qi + 2);
      const parts = head.split(':');
      host = parts[0] || '';
      port = parts[1] || '';
      try {
        name = b64ToText(getParam(query, 'remarks'));
      } catch (e) {
        name = '';
      }
    } else if (proto === 'ss') {
      // ss://b64(method:pass)@host:port#name  |  ss://b64(method:pass@host:port)#name
      let urlStr = 'ss://' + body;
      if (body.indexOf('@') === -1) {
        const preHash = body.split('#')[0];
        const hashPart = body.indexOf('#') === -1 ? '' : body.slice(body.indexOf('#'));
        try {
          const d = b64ToText(preHash);
          if (/@/.test(d)) urlStr = 'ss://' + d + hashPart;
        } catch (e) {
          /* not a base64 blob */
        }
      }
      const u = new URL(urlStr);
      host = u.hostname;
      port = u.port;
      name = takeName(u.hash);
      // username may be base64(method:password) — surface the method as fallback name
      if (!name && u.username) {
        try {
          const d = b64ToText(u.username);
          if (/^[^:]+:.+/.test(d)) name = d.split(':')[0];
        } catch (e) {
          if (u.username.indexOf(':') !== -1) name = u.username.split(':')[0];
        }
      }
    } else {
      // vless:// trojan:// tuic:// hy2:// wireguard:// … standard URL shape
      const u = new URL(proto + '://' + body);
      host = u.hostname;
      port = u.port;
      name = takeName(u.hash);
    }
  } catch (e) {
    // best-effort fallback for odd lines
    const hm = body.match(/@([^/?#:]+)(?::(\d+))?/);
    if (hm) {
      host = hm[1];
      port = hm[2] || '';
    }
    const hi = body.indexOf('#');
    if (hi !== -1) name = takeName(body.slice(hi));
  }

  const label =
    name ||
    (host ? host + (port ? ':' + port : '') : uri.slice(0, 48) + (uri.length > 48 ? '…' : ''));

  return { proto: proto, name: label, host: host, port: port, uri: uri };
}

/* Promo/advertisement entries the user asked to hide from the site. */
function isPromoConfig(c) {
  return /پنل رایگان|PANEL_ZEUS/i.test(c.name || "");
}

/* Parse a whole subscription response into config objects. */
function parseSubscription(raw) {
  return extractConfigLines(raw)
    .map(parseConfigLine)
    .filter(function (c) { return c !== null && !isPromoConfig(c); });
}
