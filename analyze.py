#!/usr/bin/env python3
"""
PCAP / PCAPng Analyzer — Advanced Website & Network Inspector
=============================================================
Pure Python stdlib — zero external dependencies.

Features:
  ✓ Reads .pcap (classic) 
  ✓ Identifies websites by name (brand mapping: Google, YouTube, Meta…)
  ✓ TLS SNI extraction (HTTPS site detection)
  ✓ HTTP Host header extraction
  ✓ DNS query/answer parsing with CNAME chain resolution
  ✓ Protocol breakdown (TCP/UDP/ICMP/etc.)
  ✓ Top external IPs with reverse-DNS name lookup
  ✓ User-Agent fingerprinting (browser/OS detection)
  ✓ Suspicious traffic detection (non-standard ports, plaintext creds, etc.)
  ✓ Connection timeline & bandwidth per site
  ✓ JSON export

Usage:
    python3 pcap_analyzer.py capture.pcap
    python3 pcap_analyzer.py capture.pcapng
    python3 pcap_analyzer.py capture.pcap  --json > report.json
    python3 pcap_analyzer.py capture.pcap  --filter youtube
    python3 pcap_analyzer.py capture.pcap  --top 30 --no-ports
    python3 pcap_analyzer.py capture.pcap  --resolve      # live rDNS lookup
"""

import struct, socket, sys, json, argparse, os, re, ipaddress
from collections import defaultdict, Counter
from datetime import datetime, timezone


# ═══════════════════════════════════════════════════════════════════════════════
#  FILE READERS  —  classic PCAP + PCAPng
# ═══════════════════════════════════════════════════════════════════════════════

def _read_exact(f, n):
    d = f.read(n)
    if len(d) < n:
        raise EOFError("Truncated file")
    return d

# ── Classic PCAP ──────────────────────────────────────────────────────────────
_GH_LE = struct.Struct("<IHHiIII")
_GH_BE = struct.Struct(">IHHiIII")
_PH_LE = struct.Struct("<IIII")
_PH_BE = struct.Struct(">IIII")
_MAGIC = {
    0xA1B2C3D4: (False, False, _GH_LE, _PH_LE),
    0xD4C3B2A1: (True,  False, _GH_BE, _PH_BE),
    0xA1B23C4D: (False, True,  _GH_LE, _PH_LE),
    0x4D3CB2A1: (True,  True,  _GH_BE, _PH_BE),
}

class PcapReader:
    def __init__(self, path):
        self._f = open(path, "rb")
        raw4 = self._f.read(4)
        magic = struct.unpack("<I", raw4)[0]
        if magic not in _MAGIC:
            raise ValueError(f"Not a classic PCAP (magic=0x{magic:08X})")
        be, ns, gh, ph = _MAGIC[magic]
        self._ns, self._ph = ns, ph
        rest = _read_exact(self._f, gh.size - 4)
        hdr = gh.unpack(raw4 + rest)
        self.link_type = hdr[6]
        self.interfaces = [{"link_type": self.link_type, "name": "eth0"}]

    def __iter__(self): return self
    def __next__(self):
        raw = self._f.read(self._ph.size)
        if not raw or len(raw) < self._ph.size: raise StopIteration
        ts_sec, ts_frac, cap_len, orig_len = self._ph.unpack(raw)
        ts = ts_sec + ts_frac / (1_000_000_000 if self._ns else 1_000_000)
        data = _read_exact(self._f, cap_len)
        return ts, orig_len, data, 0   # (ts, orig_len, data, iface_idx)
    def close(self): self._f.close()


# ── PCAPng ────────────────────────────────────────────────────────────────────
_PCAPNG_MAGIC = 0x0A0D0D0A
_SHB  = 0x0A0D0D0A
_IDB  = 0x00000001
_EPB  = 0x00000006
_SPB  = 0x00000003
_OBS  = 0x00000002   # obsolete packet block

class PcapngReader:
    """
    Reads PCAPng files.  Supports SHB, IDB, EPB, SPB, OBB.
    Handles both LE and BE byte-orders, and multiple interfaces.
    """
    def __init__(self, path):
        self._f = open(path, "rb")
        self._le = True   # default; SHB will set properly
        self.interfaces = []
        self._buf = []    # buffered (ts, orig, data, iface) tuples
        self._parse_shb()

    def _u32(self, b, o=0): return struct.unpack_from("<I" if self._le else ">I", b, o)[0]
    def _u16(self, b, o=0): return struct.unpack_from("<H" if self._le else ">H", b, o)[0]
    def _u64(self, b, o=0): return struct.unpack_from("<Q" if self._le else ">Q", b, o)[0]

    def _read_block(self):
        hdr = self._f.read(8)
        if not hdr or len(hdr) < 8: return None, None
        btype = struct.unpack_from("<I", hdr, 0)[0]
        blen  = self._u32(hdr, 4)
        if blen < 12: return btype, b""
        body = self._f.read(blen - 12)   # minus type(4)+len(4)+trailing_len(4)
        self._f.read(4)                   # trailing block length
        return btype, body

    def _parse_shb(self):
        hdr = self._f.read(8)
        if not hdr or len(hdr) < 8:
            raise ValueError("Empty PCAPng file")
        btype = struct.unpack_from("<I", hdr, 0)[0]
        if btype != _PCAPNG_MAGIC:
            raise ValueError(f"Not a PCAPng file (block type 0x{btype:08X})")
        blen_le = struct.unpack_from("<I", hdr, 4)[0]
        body = self._f.read(blen_le - 12)
        self._f.read(4)
        bom = struct.unpack_from("<I", body, 0)[0]
        self._le = (bom == 0x1A2B3C4D)

    def _parse_idb(self, body):
        lt = self._u16(body, 0)
        tsres = 6   # default: microsecond
        off = 4
        while off + 4 <= len(body):
            ot = self._u16(body, off); ol = self._u16(body, off+2); off += 4
            if ot == 9 and ol >= 1:   # if_tsresol
                r = body[off]
                if r & 0x80: tsres = int(1e9 / (2 ** (r & 0x7F)))
                else:        tsres = int(1e9 / (10 ** (r & 0x7F)))
            off += ol + ((-ol) % 4)
        self.interfaces.append({"link_type": lt, "tsresol": tsres, "name": f"if{len(self.interfaces)}"})
        return lt

    def _parse_epb(self, body):
        if len(body) < 20: return
        iface_id = self._u32(body, 0)
        ts_hi    = self._u32(body, 4)
        ts_lo    = self._u32(body, 8)
        cap_len  = self._u32(body, 12)
        orig_len = self._u32(body, 16)
        data     = body[20:20+cap_len]
        iface    = self.interfaces[iface_id] if iface_id < len(self.interfaces) else self.interfaces[0]
        tsres    = iface.get("tsresol", 6)
        ts_raw   = (ts_hi << 32) | ts_lo
        ts       = ts_raw / (10 ** tsres) if tsres < 10 else ts_raw / tsres
        self._buf.append((ts, orig_len, data, iface_id))

    def _parse_spb(self, body):
        if len(body) < 8: return
        orig_len = self._u32(body, 0)
        cap_len  = self._u32(body, 4)
        data     = body[8:8+cap_len]
        iface    = self.interfaces[0] if self.interfaces else {"link_type": 1}
        self._buf.append((0.0, orig_len, data, 0))

    def _parse_obs(self, body):   # obsolete packet block (type 2)
        if len(body) < 16: return
        cap_len  = self._u32(body, 8)
        orig_len = self._u32(body, 12)
        data     = body[16:16+cap_len]
        self._buf.append((0.0, orig_len, data, 0))

    @property
    def link_type(self):
        return self.interfaces[0]["link_type"] if self.interfaces else 1

    def __iter__(self): return self
    def __next__(self):
        while not self._buf:
            btype, body = self._read_block()
            if btype is None: raise StopIteration
            if btype == _IDB:  self._parse_idb(body)
            elif btype == _EPB: self._parse_epb(body)
            elif btype == _SPB: self._parse_spb(body)
            elif btype == _OBS: self._parse_obs(body)
            elif btype == _SHB: pass   # new section — interfaces reset would go here
        return self._buf.pop(0)
    def close(self): self._f.close()


def open_capture(path):
    """Auto-detect PCAP vs PCAPng and return the right reader."""
    with open(path, "rb") as f:
        magic4 = f.read(4)
    if len(magic4) < 4:
        raise ValueError("File too small")
    magic_le = struct.unpack("<I", magic4)[0]
    if magic_le == _PCAPNG_MAGIC:
        return PcapngReader(path)
    elif magic_le in _MAGIC:
        return PcapReader(path)
    else:
        raise ValueError(
            f"Unrecognised file format (magic=0x{magic_le:08X}). "
            "Expected a .pcap or .pcapng file.")


# ═══════════════════════════════════════════════════════════════════════════════
#  LOW-LEVEL PROTOCOL DECODERS
# ═══════════════════════════════════════════════════════════════════════════════

def _u16be(b, o): return struct.unpack_from(">H", b, o)[0]
def _u32be(b, o): return struct.unpack_from(">I", b, o)[0]
def _ip4(b):   return ".".join(str(x) for x in b)
def _ip6(b):
    try:    return socket.inet_ntop(socket.AF_INET6, bytes(b))
    except: return ":".join(f"{b[i]:02x}{b[i+1]:02x}" for i in range(0,16,2))

def decode_ethernet(d):
    if len(d) < 14: return None
    dst = ":".join(f"{x:02x}" for x in d[0:6])
    src = ":".join(f"{x:02x}" for x in d[6:12])
    et = _u16be(d, 12); pl = d[14:]
    while et == 0x8100 and len(pl) >= 4:   # strip VLAN
        et = _u16be(pl, 2); pl = pl[4:]
    return dst, src, et, pl

def decode_ipv4(d):
    if len(d) < 20: return None
    ihl = (d[0] & 0xF) * 4
    if ihl < 20 or len(d) < ihl: return None
    return _ip4(d[12:16]), _ip4(d[16:20]), d[9], d[ihl:], d[8], _u16be(d, 2)

def decode_ipv6(d):
    if len(d) < 40: return None
    return _ip6(d[8:24]), _ip6(d[24:40]), d[6], d[40:], d[7], _u16be(d, 4)

def decode_tcp(d):
    if len(d) < 20: return None
    off = (d[12] >> 4) * 4
    pl  = d[off:] if len(d) >= off else b""
    return _u16be(d,0), _u16be(d,2), _u32be(d,4), _u32be(d,8), d[13], _u16be(d,14), pl

def decode_udp(d):
    if len(d) < 8: return None
    return _u16be(d,0), _u16be(d,2), _u16be(d,4), d[8:]

def decode_icmp(d):
    if len(d) < 4: return None
    return d[0], d[1]   # type, code


# ═══════════════════════════════════════════════════════════════════════════════
#  TLS / SNI EXTRACTOR
# ═══════════════════════════════════════════════════════════════════════════════

def extract_tls_sni(data):
    try:
        if len(data) < 5 or data[0] != 0x16: return None
        rec_len = _u16be(data, 3)
        if len(data) < 5 + rec_len: return None
        hs = data[5:5+rec_len]
        if len(hs) < 4 or hs[0] != 0x01: return None
        hs_len = (hs[1]<<16) | _u16be(hs, 2)
        body = hs[4:4+hs_len]
        if len(body) < 34: return None
        off = 34
        sid = body[off]; off += 1 + sid
        if off+2 > len(body): return None
        cs = _u16be(body, off); off += 2 + cs
        if off >= len(body): return None
        cm = body[off]; off += 1 + cm
        if off+2 > len(body): return None
        et = _u16be(body, off); off += 2
        ext_end = off + et
        while off+4 <= ext_end and off+4 <= len(body):
            etype = _u16be(body, off); elen = _u16be(body, off+2); off += 4
            ed = body[off:off+elen]; off += elen
            if etype == 0x0000 and len(ed) >= 5 and ed[2] == 0x00:
                nl = _u16be(ed, 3)
                if len(ed) >= 5+nl:
                    return ed[5:5+nl].decode("ascii", errors="replace")
    except Exception: pass
    return None

def extract_tls_version(data):
    """Return TLS version string from ClientHello or ServerHello."""
    try:
        if len(data) < 5 or data[0] != 0x16: return None
        ver = _u16be(data, 1)
        return {0x0301:"TLS 1.0",0x0302:"TLS 1.1",0x0303:"TLS 1.2",0x0304:"TLS 1.3"}.get(ver)
    except: return None


# ═══════════════════════════════════════════════════════════════════════════════
#  HTTP EXTRACTOR
# ═══════════════════════════════════════════════════════════════════════════════

_HTTP_REQ = {b"GET ",b"POST ",b"PUT ",b"DELETE ",b"HEAD ",
             b"OPTIONS ",b"PATCH ",b"CONNECT ",b"TRACE "}

def extract_http(payload):
    if not payload: return None
    is_req = any(payload.startswith(m) for m in _HTTP_REQ)
    is_res = payload.startswith(b"HTTP/1") or payload.startswith(b"HTTP/2")
    if not is_req and not is_res: return None
    try:
        end = payload.find(b"\r\n\r\n")
        raw = payload[:end] if end != -1 else payload[:8192]
        lines = raw.split(b"\r\n")
        first = lines[0].decode("latin-1", errors="replace")
        hdrs = {}
        for ln in lines[1:]:
            if b":" in ln:
                k, _, v = ln.partition(b":")
                hdrs[k.strip().lower().decode("latin-1","replace")] = v.strip().decode("latin-1","replace")
        if is_req:
            pts = first.split(" ")
            return {"type":"request","method":pts[0] if pts else "",
                    "path":pts[1] if len(pts)>1 else "/","version":pts[2] if len(pts)>2 else "",
                    "host":hdrs.get("host",""),"user_agent":hdrs.get("user-agent",""),
                    "referer":hdrs.get("referer",""),"content_type":hdrs.get("content-type",""),
                    "authorization": "present" if "authorization" in hdrs else "",
                    "cookie":"present" if "cookie" in hdrs else ""}
        else:
            return {"type":"response","status":first,
                    "content_type":hdrs.get("content-type",""),"server":hdrs.get("server",""),
                    "location":hdrs.get("location",""),"content_length":hdrs.get("content-length",""),
                    "set_cookie":"present" if "set-cookie" in hdrs else ""}
    except: return None


# ═══════════════════════════════════════════════════════════════════════════════
#  DNS EXTRACTOR
# ═══════════════════════════════════════════════════════════════════════════════

def _dns_name(data, off):
    labels = []; visited = set()
    while off < len(data):
        l = data[off]
        if l == 0: off += 1; break
        elif (l & 0xC0) == 0xC0:
            if off+1 >= len(data): break
            ptr = ((l & 0x3F) << 8) | data[off+1]; off += 2
            if ptr in visited: break
            visited.add(ptr); sub,_ = _dns_name(data, ptr); labels.append(sub); return ".".join(labels), off
        else:
            off += 1; labels.append(data[off:off+l].decode("latin-1","replace")); off += l
    return ".".join(labels), off

_DNS_TYPES = {1:"A",2:"NS",5:"CNAME",6:"SOA",12:"PTR",15:"MX",16:"TXT",
              28:"AAAA",33:"SRV",43:"DS",46:"RRSIG",255:"ANY",65:"HTTPS"}

def extract_dns(payload):
    if len(payload) < 12: return None
    try:
        flags  = _u16be(payload,2); qr = (flags>>15)&1; op = (flags>>11)&0xF
        rcode  = flags & 0xF
        if op != 0: return None
        qdc = _u16be(payload,4); anc = _u16be(payload,6)
        off = 12; queries = []
        for _ in range(qdc):
            n, off = _dns_name(payload, off)
            if off+4 > len(payload): break
            qt = _u16be(payload, off); off += 4
            queries.append({"name":n,"type":_DNS_TYPES.get(qt,str(qt))})
        answers = []
        if qr:
            for _ in range(anc):
                if off >= len(payload): break
                n, off = _dns_name(payload, off)
                if off+10 > len(payload): break
                at = _u16be(payload, off); ttl = _u32be(payload, off+4); rdl = _u16be(payload, off+8); off += 10
                rd = payload[off:off+rdl]; off += rdl
                if at == 1 and len(rd) == 4:
                    answers.append({"name":n,"type":"A","value":_ip4(rd),"ttl":ttl})
                elif at == 28 and len(rd) == 16:
                    answers.append({"name":n,"type":"AAAA","value":_ip6(rd),"ttl":ttl})
                elif at == 5:
                    cn,_ = _dns_name(payload, off-rdl); answers.append({"name":n,"type":"CNAME","value":cn,"ttl":ttl})
                elif at == 12:
                    ptr,_ = _dns_name(payload, off-rdl); answers.append({"name":n,"type":"PTR","value":ptr,"ttl":ttl})
        return {"is_response":bool(qr),"rcode":rcode,"queries":queries,"answers":answers}
    except: return None


# ═══════════════════════════════════════════════════════════════════════════════
#  BRAND / WEBSITE IDENTIFICATION
# ═══════════════════════════════════════════════════════════════════════════════

# Maps domain fragments → (Brand Name, Category, Icon)
_BRAND_MAP = [
    # Google ecosystem
    (r"(^|\.)google\.",          "Google",           "Search / Productivity"),
    (r"(^|\.)googleapis\.",      "Google APIs",      "Cloud / APIs"),
    (r"(^|\.)googleusercontent\.","Google Content",  "Cloud / CDN"),
    (r"(^|\.)gstatic\.",         "Google Static",    "CDN"),
    (r"(^|\.)gmail\.",           "Gmail",            "Email"),
    (r"(^|\.)youtube\.",         "YouTube",          "Video Streaming"),
    (r"(^|\.)ytimg\.",           "YouTube Images",   "CDN"),
    (r"(^|\.)googlevideo\.",     "YouTube Video",    "Video Streaming"),
    (r"(^|\.)ggpht\.",           "Google Photos",    "Photos / CDN"),
    (r"(^|\.)doubleclick\.",     "Google Ads",       "Advertising"),
    (r"(^|\.)googlesyndication\.","Google Ads",      "Advertising"),
    (r"(^|\.)googleadservices\.", "Google Ads",      "Advertising"),
    (r"(^|\.)goog\b",            "Google Short",     "URL Shortener"),
    (r"(^|\.)android\.",         "Android/Google",   "OS / Mobile"),
    (r"(^|\.)play\.google\.",    "Google Play",      "App Store"),
    (r"(^|\.)maps\.google\.",    "Google Maps",      "Maps"),
    # Meta / Facebook
    (r"(^|\.)facebook\.",        "Facebook",         "Social Media"),
    (r"(^|\.)fbcdn\.",           "Facebook CDN",     "CDN"),
    (r"(^|\.)instagram\.",       "Instagram",        "Social Media"),
    (r"(^|\.)whatsapp\.",        "WhatsApp",         "Messaging"),
    (r"(^|\.)messenger\.",       "Messenger",        "Messaging"),
    (r"(^|\.)meta\.",            "Meta",             "Social Media"),
    (r"(^|\.)oculus\.",          "Meta VR",          "VR / Gaming"),
    # Microsoft
    (r"(^|\.)microsoft\.",       "Microsoft",        "Software / Cloud"),
    (r"(^|\.)windows\.",         "Windows Update",   "OS / Software"),
    (r"(^|\.)live\.",            "Microsoft Live",   "Email / Cloud"),
    (r"(^|\.)outlook\.",         "Outlook",          "Email"),
    (r"(^|\.)office\.",          "Microsoft Office", "Productivity"),
    (r"(^|\.)azure\.",           "Microsoft Azure",  "Cloud"),
    (r"(^|\.)bing\.",            "Bing",             "Search"),
    (r"(^|\.)msn\.",             "MSN",              "News / Portal"),
    (r"(^|\.)teams\.",           "MS Teams",         "Collaboration"),
    (r"(^|\.)skype\.",           "Skype",            "Messaging"),
    (r"(^|\.)xbox\.",            "Xbox",             "Gaming"),
    (r"(^|\.)linkedin\.",        "LinkedIn",         "Social / Professional"),
    (r"(^|\.)github\.",          "GitHub",           "Dev / Code Hosting"),
    (r"(^|\.)visualstudio\.",    "Visual Studio",    "Dev Tools"),
    # Apple
    (r"(^|\.)apple\.",           "Apple",            "Software / Hardware"),
    (r"(^|\.)icloud\.",          "iCloud",           "Cloud Storage"),
    (r"(^|\.)itunes\.",          "iTunes/App Store", "Media / App Store"),
    (r"(^|\.)mzstatic\.",        "App Store CDN",    "CDN"),
    (r"(^|\.)appleiphoneactivation\.", "Apple Activation","Device"),
    # Amazon / AWS
    (r"(^|\.)amazon\.",          "Amazon",           "E-commerce / Cloud"),
    (r"(^|\.)amazonaws\.",       "AWS",              "Cloud"),
    (r"(^|\.)cloudfront\.",      "CloudFront CDN",   "CDN"),
    (r"(^|\.)alexa\.",           "Alexa",            "IoT / Assistant"),
    (r"(^|\.)twitch\.",          "Twitch",           "Video Streaming"),
    # Netflix
    (r"(^|\.)netflix\.",         "Netflix",          "Video Streaming"),
    (r"(^|\.)nflxvideo\.",       "Netflix Video",    "Video Streaming"),
    (r"(^|\.)nflximg\.",         "Netflix Images",   "CDN"),
    # Cloudflare
    (r"(^|\.)cloudflare\.",      "Cloudflare",       "CDN / Security"),
    (r"(^|\.)cloudflarestorage\.","Cloudflare R2",   "Cloud Storage"),
    (r"1\.1\.1\.1",              "Cloudflare DNS",   "DNS"),
    # Twitter / X
    (r"(^|\.)twitter\.",         "Twitter / X",      "Social Media"),
    (r"(^|\.)twimg\.",           "Twitter CDN",      "CDN"),
    (r"(^|\.)x\.com",           "X (Twitter)",      "Social Media"),
    # TikTok / ByteDance
    (r"(^|\.)tiktok\.",          "TikTok",           "Social Media / Video"),
    (r"(^|\.)bytedance\.",       "ByteDance",        "Social Media"),
    (r"(^|\.)musical\.ly",       "TikTok (old)",     "Social Media"),
    # Snapchat
    (r"(^|\.)snapchat\.",        "Snapchat",         "Social Media"),
    # Reddit
    (r"(^|\.)reddit\.",          "Reddit",           "Social Media / Forum"),
    (r"(^|\.)redd\.it",          "Reddit Short",     "Social Media"),
    (r"(^|\.)redditmedia\.",      "Reddit Media",    "CDN"),
    # Zoom
    (r"(^|\.)zoom\.",            "Zoom",             "Video Conferencing"),
    (r"(^|\.)zoomgov\.",         "Zoom Gov",         "Video Conferencing"),
    # Spotify
    (r"(^|\.)spotify\.",         "Spotify",          "Music Streaming"),
    (r"(^|\.)scdn\.co",          "Spotify CDN",      "CDN"),
    # Telegram
    (r"(^|\.)telegram\.",        "Telegram",         "Messaging"),
    (r"(^|\.)t\.me",             "Telegram",         "Messaging"),
    # Discord
    (r"(^|\.)discord\.",         "Discord",          "Messaging / Gaming"),
    (r"(^|\.)discordapp\.",      "Discord",          "Messaging / Gaming"),
    # Slack
    (r"(^|\.)slack\.",           "Slack",            "Collaboration"),
    (r"(^|\.)slackb\.",          "Slack CDN",        "CDN"),
    # Adobe
    (r"(^|\.)adobe\.",           "Adobe",            "Creative Software"),
    (r"(^|\.)adobedtm\.",        "Adobe Analytics",  "Analytics"),
    # Akamai / CDNs
    (r"(^|\.)akamai\.",          "Akamai CDN",       "CDN"),
    (r"(^|\.)akamaihd\.",        "Akamai CDN",       "CDN"),
    (r"(^|\.)fastly\.",          "Fastly CDN",       "CDN"),
    (r"(^|\.)edgecastcdn\.",     "Edgecast CDN",     "CDN"),
    (r"(^|\.)cdninstagram\.",    "Instagram CDN",    "CDN"),
    # Analytics / Tracking
    (r"(^|\.)analytics\.",       "Analytics",        "Analytics"),
    (r"(^|\.)segment\.",         "Segment",          "Analytics"),
    (r"(^|\.)mixpanel\.",        "Mixpanel",         "Analytics"),
    (r"(^|\.)amplitude\.",       "Amplitude",        "Analytics"),
    (r"(^|\.)newrelic\.",        "New Relic",        "APM / Monitoring"),
    (r"(^|\.)datadog\.",         "Datadog",          "Monitoring"),
    (r"(^|\.)hotjar\.",          "Hotjar",           "Analytics"),
    # DNS resolvers
    (r"8\.8\.8\.8",              "Google DNS",       "DNS"),
    (r"8\.8\.4\.4",              "Google DNS",       "DNS"),
    (r"9\.9\.9\.9",              "Quad9 DNS",        "DNS"),
    (r"208\.67\.222\.",          "OpenDNS",          "DNS"),
    # Payment
    (r"(^|\.)paypal\.",          "PayPal",           "Payment"),
    (r"(^|\.)stripe\.",          "Stripe",           "Payment"),
    (r"(^|\.)braintree\.",       "Braintree",        "Payment"),
    # VPN / Privacy
    (r"(^|\.)nordvpn\.",         "NordVPN",          "VPN"),
    (r"(^|\.)expressvpn\.",      "ExpressVPN",       "VPN"),
    (r"(^|\.)protonvpn\.",       "ProtonVPN",        "VPN"),
    (r"(^|\.)torproject\.",      "Tor Project",      "Privacy"),
    # Misc popular
    (r"(^|\.)wikipedia\.",       "Wikipedia",        "Reference"),
    (r"(^|\.)wikimedia\.",       "Wikimedia",        "Reference / CDN"),
    (r"(^|\.)ebay\.",            "eBay",             "E-commerce"),
    (r"(^|\.)shopify\.",         "Shopify",          "E-commerce"),
    (r"(^|\.)dropbox\.",         "Dropbox",          "Cloud Storage"),
    (r"(^|\.)box\.",             "Box",              "Cloud Storage"),
    (r"(^|\.)github\.io",        "GitHub Pages",     "Dev / Hosting"),
    (r"(^|\.)npm\.",             "npm Registry",     "Dev / Packages"),
    (r"(^|\.)pypi\.",            "PyPI",             "Dev / Packages"),
    (r"(^|\.)docker\.",          "Docker",           "Dev / Containers"),
]

# Compile patterns once
_BRAND_PATTERNS = [(re.compile(pat, re.I), brand, cat) for pat, brand, cat in _BRAND_MAP]

def identify_brand(hostname):
    """Return (brand_name, category) or (None, None)."""
    for pat, brand, cat in _BRAND_PATTERNS:
        if pat.search(hostname):
            return brand, cat
    return None, None


# ═══════════════════════════════════════════════════════════════════════════════
#  USER-AGENT FINGERPRINTING
# ═══════════════════════════════════════════════════════════════════════════════

def fingerprint_ua(ua):
    if not ua: return "Unknown"
    ua_l = ua.lower()
    browser = os_name = ""
    if "edg/" in ua_l or "edge/" in ua_l: browser = "Edge"
    elif "opr/" in ua_l or "opera" in ua_l: browser = "Opera"
    elif "chrome/" in ua_l: browser = "Chrome"
    elif "firefox/" in ua_l: browser = "Firefox"
    elif "safari/" in ua_l and "chrome" not in ua_l: browser = "Safari"
    elif "curl/" in ua_l: browser = "cURL"
    elif "python" in ua_l: browser = "Python"
    elif "wget" in ua_l: browser = "Wget"
    elif "okhttp" in ua_l: browser = "OkHttp (Android)"
    elif "cfnetwork" in ua_l: browser = "CFNetwork (Apple)"
    elif "dalvik" in ua_l: browser = "Android Dalvik"
    elif "java" in ua_l: browser = "Java"
    elif "go-http" in ua_l: browser = "Go"
    if "windows nt 10" in ua_l: os_name = "Windows 10/11"
    elif "windows nt 6.3" in ua_l: os_name = "Windows 8.1"
    elif "windows nt 6.1" in ua_l: os_name = "Windows 7"
    elif "mac os x" in ua_l: os_name = "macOS"
    elif "iphone" in ua_l: os_name = "iOS (iPhone)"
    elif "ipad" in ua_l: os_name = "iOS (iPad)"
    elif "android" in ua_l:
        m = re.search(r"android ([\d.]+)", ua_l)
        os_name = f"Android {m.group(1)}" if m else "Android"
    elif "linux" in ua_l: os_name = "Linux"
    elif "cros" in ua_l: os_name = "ChromeOS"
    parts = [p for p in [browser, os_name] if p]
    return " / ".join(parts) if parts else "Unknown Client"


# ═══════════════════════════════════════════════════════════════════════════════
#  SUSPICIOUS TRAFFIC DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

_SUSPICIOUS_PORTS = {
    23:"Telnet (plaintext)",4444:"Metasploit default",1234:"Common backdoor",
    31337:"Elite/backdoor",12345:"NetBus RAT",6666:"IRC/botnet",6667:"IRC/botnet",
    6668:"IRC/botnet",6669:"IRC/botnet",1080:"SOCKS proxy",8888:"Alt HTTP/Jupyter",
    9001:"Tor relay",9050:"Tor SOCKS",9150:"Tor Browser SOCKS",
    4443:"Alt HTTPS",2222:"Alt SSH",8022:"Alt SSH",
}

def check_suspicious(sport, dport, payload, proto):
    flags = []
    for port in (sport, dport):
        if port in _SUSPICIOUS_PORTS:
            flags.append(f"Suspicious port {port}: {_SUSPICIOUS_PORTS[port]}")
    if payload:
        pl_low = payload[:200].lower()
        if b"password" in pl_low or b"passwd" in pl_low:
            flags.append("Possible plaintext credential (keyword: password)")
        if b"authorization: basic" in pl_low:
            flags.append("HTTP Basic Auth (base64-encoded credentials)")
        if b"user" in pl_low and b"pass" in pl_low and proto == "TCP" and dport not in (80,443,8080,8443):
            flags.append("Possible plaintext login on non-standard port")
    return flags


# ═══════════════════════════════════════════════════════════════════════════════
#  PRIVATE IP CHECK
# ═══════════════════════════════════════════════════════════════════════════════

_PRIV_NETS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("100.64.0.0/10"),
]

def _is_private(ip):
    try:
        a = ipaddress.IPv4Address(ip)
        return any(a in n for n in _PRIV_NETS)
    except: return True   # IPv6 or invalid → treat as non-public

def _is_multicast(ip):
    try: return ipaddress.ip_address(ip).is_multicast
    except: return False


# ═══════════════════════════════════════════════════════════════════════════════
#  WELL-KNOWN PORT TABLE
# ═══════════════════════════════════════════════════════════════════════════════

WELL_KNOWN_PORTS = {
    20:"FTP-data",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    67:"DHCP-server",68:"DHCP-client",69:"TFTP",80:"HTTP",110:"POP3",
    123:"NTP",143:"IMAP",161:"SNMP",162:"SNMP-trap",179:"BGP",
    443:"HTTPS",465:"SMTPS",514:"Syslog",587:"SMTP-sub",
    636:"LDAPS",853:"DoT",993:"IMAPS",995:"POP3S",
    1194:"OpenVPN",1433:"MSSQL",1723:"PPTP",3306:"MySQL",3389:"RDP",
    5060:"SIP",5061:"SIPS",5228:"GCM/FCM",
    8080:"HTTP-alt",8443:"HTTPS-alt",9200:"Elasticsearch",
}

PROTO_NAMES = {
    1:"ICMP",6:"TCP",17:"UDP",41:"IPv6-encap",47:"GRE",
    50:"ESP",51:"AH",58:"ICMPv6",89:"OSPF",132:"SCTP",
}


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

class PcapAnalyzer:
    def __init__(self, resolve_rdns=False):
        self.resolve_rdns = resolve_rdns

        # Website tracking
        self.http_hosts    = Counter()
        self.https_sni     = Counter()
        self.dns_queries   = Counter()
        self.dns_answers   = defaultdict(set)   # domain → {IPs}
        self.dns_ptr       = {}                  # IP → PTR name
        self.site_bytes    = defaultdict(int)    # hostname → bytes
        self.site_first    = {}                  # hostname → first seen ts
        self.site_last     = {}                  # hostname → last seen ts
        self.tls_versions  = Counter()

        # HTTP detail
        self.http_requests  = []
        self.http_responses = []
        self.user_agents    = Counter()

        # Network stats
        self.connections   = defaultdict(lambda:{"pkts":0,"bytes":0,"ts_first":None,"ts_last":None})
        self.external_ips  = Counter()
        self.proto_counts  = Counter()
        self.port_counts   = Counter()
        self.icmp_types    = Counter()

        # Suspicious
        self.suspicious    = []

        # Timing
        self.first_ts = self.last_ts = None
        self.total_packets = self.total_bytes = 0
        self.interfaces_seen = Counter()

    # ── helpers ───────────────────────────────────────────────────────────────

    def _tick(self, ts):
        if self.first_ts is None or ts < self.first_ts: self.first_ts = ts
        if self.last_ts  is None or ts > self.last_ts:  self.last_ts  = ts

    def _conn(self, key, ts, nb):
        c = self.connections[key]
        c["pkts"] += 1; c["bytes"] += nb
        if c["ts_first"] is None or ts < c["ts_first"]: c["ts_first"] = ts
        if c["ts_last"]  is None or ts > c["ts_last"]:  c["ts_last"]  = ts

    def _site_touch(self, host, ts, nb):
        if not host: return
        self.site_bytes[host] += nb
        if host not in self.site_first: self.site_first[host] = ts
        self.site_last[host] = ts

    # ── entry point ───────────────────────────────────────────────────────────

    def process(self, reader):
        for item in reader:
            ts, orig_len, data, iface_idx = item
            self._tick(ts)
            self.total_packets += 1
            self.total_bytes   += orig_len
            self.interfaces_seen[iface_idx] += 1
            lt = reader.interfaces[iface_idx]["link_type"] if iface_idx < len(reader.interfaces) else reader.link_type
            if lt == 1:         self._eth(ts, orig_len, data)
            elif lt in (101, 228, 12): self._ip(ts, orig_len, data)
            # lt 12 = raw (some BSD captures)

    def _eth(self, ts, nb, d):
        r = decode_ethernet(d)
        if not r: return
        _, _, et, pl = r
        if et == 0x0800: self._ipv4(ts, nb, pl)
        elif et == 0x86DD: self._ipv6(ts, nb, pl)

    def _ip(self, ts, nb, d):
        if not d: return
        v = d[0] >> 4
        if v == 4: self._ipv4(ts, nb, d)
        elif v == 6: self._ipv6(ts, nb, d)

    def _ipv4(self, ts, nb, d):
        r = decode_ipv4(d)
        if r: self._net(ts, nb, r[0], r[1], r[2], r[3])

    def _ipv6(self, ts, nb, d):
        r = decode_ipv6(d)
        if r: self._net(ts, nb, r[0], r[1], r[2], r[3])

    def _net(self, ts, nb, src, dst, proto, payload):
        pname = PROTO_NAMES.get(proto, str(proto))
        self.proto_counts[pname] += 1
        for ip in (src, dst):
            if not _is_private(ip) and not _is_multicast(ip) and ":" not in ip:
                self.external_ips[ip] += 1
        if proto == 6:  self._tcp(ts, nb, src, dst, payload)
        elif proto == 17: self._udp(ts, nb, src, dst, payload)
        elif proto == 1:
            r = decode_icmp(payload)
            if r: self.icmp_types[f"type{r[0]}/code{r[1]}"] += 1

    def _tcp(self, ts, nb, src, dst, d):
        r = decode_tcp(d)
        if not r: return
        sp, dp, _, _, flags, _, payload = r
        self.port_counts[min(sp,dp)] += 1
        self._conn((src,sp,dst,dp,"TCP"), ts, nb)

        # HTTP
        if dp in (80,8080,8000,3000,8081,8888,8008) or sp in (80,8080):
            h = extract_http(payload)
            if h:
                if h["type"] == "request":
                    host = h.get("host","")
                    if host:
                        self.http_hosts[host] += 1
                        self._site_touch(host, ts, nb)
                    if h.get("user_agent"):
                        self.user_agents[h["user_agent"]] += 1
                    self.http_requests.append({"ts":ts,"src":src,"dst":dst,"sport":sp,"dport":dp,**h})
                else:
                    self.http_responses.append({"ts":ts,"src":src,"dst":dst,**h})

        # HTTPS / TLS
        if dp in (443,8443,993,995,465,587,853,636,5061,4443) or sp in (443,8443):
            sni = extract_tls_sni(payload)
            if sni:
                self.https_sni[sni] += 1
                self._site_touch(sni, ts, nb)
            tv = extract_tls_version(payload)
            if tv: self.tls_versions[tv] += 1

        # Suspicious
        sus = check_suspicious(sp, dp, payload, "TCP")
        if sus:
            self.suspicious.append({"ts":ts,"src":src,"sport":sp,"dst":dst,"dport":dp,"flags":sus})

    def _udp(self, ts, nb, src, dst, d):
        r = decode_udp(d)
        if not r: return
        sp, dp, _, payload = r
        self.port_counts[min(sp,dp)] += 1
        self._conn((src,sp,dst,dp,"UDP"), ts, nb)

        if sp == 53 or dp == 53:
            dns = extract_dns(payload)
            if dns:
                for q in dns["queries"]:
                    self.dns_queries[q["name"]] += 1
                for a in dns["answers"]:
                    name = a["name"]
                    self.dns_answers[name].add(a["value"])
                    if a["type"] == "PTR":
                        # reverse-DNS answer: name is x.in-addr.arpa, value is hostname
                        self.dns_ptr[a["name"]] = a["value"]

        # rDNS live lookup
        if self.resolve_rdns:
            for ip in (src, dst):
                if not _is_private(ip) and ":" not in ip and ip not in self.dns_ptr:
                    try:
                        host = socket.gethostbyaddr(ip)[0]
                        self.dns_ptr[ip] = host
                    except: self.dns_ptr[ip] = ""

    # ── website aggregation ───────────────────────────────────────────────────

    def websites_visited(self, top=None, keyword=None):
        combined = Counter()
        for h, c in self.https_sni.items():  combined[h] += c * 4
        for h, c in self.http_hosts.items(): combined[h] += c * 4
        for d, c in self.dns_queries.items():
            if d and not d.endswith(".arpa"):
                combined[d] += c

        if keyword:
            combined = Counter({k:v for k,v in combined.items() if keyword.lower() in k.lower()})

        results = []
        for host, score in combined.most_common(top):
            ips  = list(self.dns_answers.get(host, set()))
            http = self.http_hosts.get(host, 0)
            tls  = self.https_sni.get(host, 0)
            dns  = self.dns_queries.get(host, 0)
            brand, cat = identify_brand(host)
            proto = "HTTPS" if tls else ("HTTP" if http else "DNS-only")
            bw = self.site_bytes.get(host, 0)
            results.append({
                "hostname":   host,
                "brand":      brand or _guess_brand_from_domain(host),
                "category":   cat or "Unknown",
                "protocol":   proto,
                "http_requests":     http,
                "https_connections": tls,
                "dns_queries":       dns,
                "resolved_ips":      ips,
                "bandwidth_bytes":   bw,
                "first_seen": _fmt_ts(self.site_first.get(host)),
                "last_seen":  _fmt_ts(self.site_last.get(host)),
                "score": score,
            })
        return results

    def top_user_agents(self, n=10):
        result = []
        for ua, count in self.user_agents.most_common(n):
            result.append({"user_agent": ua, "count": count, "fingerprint": fingerprint_ua(ua)})
        return result

    def summary(self):
        dur = (self.last_ts - self.first_ts) if (self.first_ts and self.last_ts) else 0
        return {
            "capture_duration_s":    round(dur, 3),
            "first_packet":          _fmt_ts(self.first_ts),
            "last_packet":           _fmt_ts(self.last_ts),
            "total_packets":         self.total_packets,
            "total_bytes":           self.total_bytes,
            "total_connections":     len(self.connections),
            "unique_external_ips":   len(self.external_ips),
            "unique_http_hosts":     len(self.http_hosts),
            "unique_tls_sni":        len(self.https_sni),
            "unique_dns_domains":    len(self.dns_queries),
            "suspicious_events":     len(self.suspicious),
            "interfaces_seen":       len(self.interfaces_seen),
        }


def _guess_brand_from_domain(host):
    """Fallback: capitalise the second-level domain."""
    parts = host.rstrip(".").split(".")
    if len(parts) >= 2:
        return parts[-2].capitalize()
    return host


# ═══════════════════════════════════════════════════════════════════════════════
#  FORMATTING HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _fmt_ts(ts):
    if ts is None: return "N/A"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def _fmt_bytes(n):
    for u in ("B","KB","MB","GB","TB"):
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"

def _bar(count, total, w=26):
    if not total: return ""
    return "█" * min(w, max(1, int(w * count / total)))

_COL = {
    "hdr":  "\033[1;36m",   # bold cyan
    "ok":   "\033[32m",
    "warn": "\033[33m",
    "err":  "\033[31m",
    "dim":  "\033[2m",
    "bold": "\033[1m",
    "rst":  "\033[0m",
}

def _c(key, text):
    if not sys.stdout.isatty(): return text
    return f"{_COL[key]}{text}{_COL['rst']}"


# ═══════════════════════════════════════════════════════════════════════════════
#  CLI PRINTERS
# ═══════════════════════════════════════════════════════════════════════════════

W = 72

def _hdr(title): print(f"\n{_c('hdr','┌─ '+title+' '+('─'*(W-4-len(title))))}")
def _end():       print(f"{_c('hdr','└'+'─'*W)}")
def _row(s):      print(f"{_c('hdr','│')}  {s}")
def _blank():     print(f"{_c('hdr','│')}")

def print_banner(path, fmt):
    size = os.path.getsize(path)
    print(_c("bold", "═"*(W+2)))
    print(_c("bold", "  PCAP / PCAPng Analyzer  —  Website & Network Inspector  v2.0"))
    print(_c("bold", "═"*(W+2)))
    print(f"  File   : {_c('ok',os.path.basename(path))}  ({_fmt_bytes(size)})")
    print(f"  Format : {_c('ok',fmt)}")
    print(_c("bold", "═"*(W+2)))

def print_summary(s):
    _hdr("CAPTURE SUMMARY")
    _row(f"Duration          : {_c('bold', str(s['capture_duration_s'])+' s')}")
    _row(f"First packet      : {s['first_packet']}")
    _row(f"Last packet       : {s['last_packet']}")
    _row(f"Total packets     : {_c('bold', '{:,}'.format(s['total_packets']))}")
    _row(f"Total data        : {_c('bold', _fmt_bytes(s['total_bytes']))}")
    _row(f"Connections       : {s['total_connections']:,}")
    _row(f"External IPs      : {s['unique_external_ips']:,}")
    _row(f"HTTP hosts seen   : {s['unique_http_hosts']:,}")
    _row(f"HTTPS/TLS SNIs    : {s['unique_tls_sni']:,}")
    _row(f"DNS domains       : {s['unique_dns_domains']:,}")
    if s["suspicious_events"]:
        _row(_c("warn", f"⚠  Suspicious events: {s['suspicious_events']}"))
    _end()

def print_websites(sites):
    if not sites: print("\n  (no websites detected)"); return
    _hdr(f"WEBSITES VISITED  [{len(sites)} found]")
    for i, s in enumerate(sites, 1):
        brand    = s["brand"] or s["hostname"]
        cat      = s["category"]
        proto    = s["protocol"]
        pcol     = "ok" if proto == "HTTPS" else ("warn" if proto == "HTTP" else "dim")
        bw_str   = _fmt_bytes(s["bandwidth_bytes"]) if s["bandwidth_bytes"] else ""
        _blank()
        _row(f"{_c('bold',f'{i:>3}.')}  {_c('bold', brand):<30} {_c(pcol,'['+proto+']')}  {_c('dim',cat)}")
        _row(f"       {_c('dim','hostname:')} {s['hostname']}")
        parts = []
        if s["http_requests"]:     parts.append(f"HTTP:{s['http_requests']}")
        if s["https_connections"]: parts.append(f"TLS:{s['https_connections']}")
        if s["dns_queries"]:       parts.append(f"DNS:{s['dns_queries']}")
        if bw_str:                 parts.append(f"BW:{bw_str}")
        if parts: _row(f"       {_c('dim','traffic:')} {' | '.join(parts)}")
        if s["resolved_ips"]:
            ips = ", ".join(s["resolved_ips"][:4])
            if len(s["resolved_ips"]) > 4: ips += f" +{len(s['resolved_ips'])-4}"
            _row(f"       {_c('dim','IPs:')} {ips}")
        if s["first_seen"] != "N/A":
            _row(f"       {_c('dim','seen:')} {s['first_seen']}  →  {s['last_seen']}")
    _end()

def print_http_requests(reqs, limit=25):
    if not reqs: return
    _hdr(f"HTTP REQUESTS  [showing {min(limit,len(reqs))} of {len(reqs)}]")
    for r in reqs[:limit]:
        host   = r.get("host", r["dst"])
        path   = r.get("path", "/")
        method = r.get("method","?")
        mcol   = "warn" if method == "POST" else "ok"
        _row(f"{_c('dim',_fmt_ts(r['ts']))}  {_c(mcol,method+' '):<9} {_c('bold','http://'+host)}{path[:50]}")
        if r.get("user_agent"):
            fp = fingerprint_ua(r["user_agent"])
            _row(f"         {_c('dim','client:')} {fp}")
        if r.get("referer"):
            _row(f"         {_c('dim','referer:')} {r['referer'][:70]}")
        if r.get("authorization"):
            _row(_c("warn","         ⚠  Authorization header present"))
    _end()

def print_dns(queries, answers, limit=30):
    if not queries: return
    _hdr(f"DNS QUERIES  [top {min(limit,len(queries))}]")
    for domain, count in queries.most_common(limit):
        if domain.endswith(".arpa"): continue
        ips = answers.get(domain, set())
        ip_str = f"→ {', '.join(list(ips)[:3])}" if ips else ""
        brand, _ = identify_brand(domain)
        brand_str = f"  {_c('dim','['+brand+']')}" if brand else ""
        _row(f"{count:>5}x  {domain:<50}{brand_str}  {_c('dim',ip_str)}")
    _end()

def print_tls(tv, sni_top):
    if not tv and not sni_top: return
    _hdr("TLS / HTTPS DETAILS")
    if tv:
        _row(_c("bold","TLS Versions observed:"))
        for ver, cnt in tv.most_common():
            col = "ok" if "1.3" in ver or "1.2" in ver else "warn"
            _row(f"  {_c(col,ver):<14} {cnt:>6,} handshakes")
    if sni_top:
        _blank()
        _row(_c("bold","Top HTTPS destinations (SNI):"))
        for sni, cnt in sni_top.most_common(15):
            brand, _ = identify_brand(sni)
            label = f"  ({brand})" if brand else ""
            _row(f"  {cnt:>6,}x  {sni}{_c('dim',label)}")
    _end()

def print_protocols(pc):
    _hdr("PROTOCOL DISTRIBUTION")
    total = sum(pc.values()) or 1
    for proto, count in pc.most_common():
        bar = _bar(count, total)
        pct = 100 * count / total
        _row(f"{proto:<10} {count:>8,}  {_c('ok',bar):<28} {pct:.1f}%")
    _end()

def print_ports(pc, limit=15):
    _hdr(f"TOP PORTS  [top {limit}]")
    for port, count in pc.most_common(limit):
        name = WELL_KNOWN_PORTS.get(port, "")
        sus  = _SUSPICIOUS_PORTS.get(port,"")
        warn = _c("warn", f"  ⚠ {sus}") if sus else ""
        _row(f"{port:>5}  {name:<18} {count:>8,} packets{warn}")
    _end()

def print_ext_ips(ext, dns_ptr, dns_answers, limit=20):
    if not ext: return
    ip2d = {ip: d for d, ips in dns_answers.items() for ip in ips}
    _hdr(f"TOP EXTERNAL IPs  [top {min(limit,len(ext))}]")
    for ip, count in ext.most_common(limit):
        dom  = ip2d.get(ip) or dns_ptr.get(ip, "")
        brand, cat = identify_brand(dom) if dom else (None, None)
        brand_str = f"  {_c('dim','['+brand+']')}" if brand else ""
        dom_str   = f"  ({dom})" if dom else ""
        _row(f"{ip:<42} {count:>7,} pkts {_c('dim',dom_str)}{brand_str}")
    _end()

def print_user_agents(uas):
    if not uas: return
    _hdr("CLIENT FINGERPRINTS  (User-Agents)")
    for entry in uas:
        _row(f"{entry['count']:>5}x  {_c('bold', entry['fingerprint'])}")
        _row(f"         {_c('dim', entry['user_agent'][:80])}")
    _end()

def print_suspicious(sus, limit=30):
    if not sus: return
    _hdr(f"SUSPICIOUS TRAFFIC  [{len(sus)} events]")
    for ev in sus[:limit]:
        _row(_c("warn", f"⚠  {_fmt_ts(ev['ts'])}  {ev['src']}:{ev['sport']} → {ev['dst']}:{ev['dport']}"))
        for f in ev["flags"]:
            _row(f"    {_c('err', f)}")
    if len(sus) > limit:
        _row(f"  … and {len(sus)-limit} more events")
    _end()

def print_categories(sites):
    cats = Counter(s["category"] for s in sites)
    if not cats: return
    _hdr("TRAFFIC CATEGORIES")
    total = sum(cats.values())
    for cat, cnt in cats.most_common():
        bar = _bar(cnt, total, 24)
        _row(f"{cat:<30} {cnt:>4} sites  {_c('ok',bar)}")
    _end()


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(
        description="Analyze .pcap or .pcapng files — identify websites, brands, protocols.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("capture",  help="Path to .pcap or .pcapng file")
    p.add_argument("--json",   action="store_true", help="Output full report as JSON")
    p.add_argument("--filter", metavar="KW",        help="Filter websites by keyword (e.g. google)")
    p.add_argument("--top",    type=int, default=50, help="Top N websites to show (default 50)")
    p.add_argument("--resolve",action="store_true", help="Live reverse-DNS lookup for external IPs (slow)")
    p.add_argument("--no-http",   action="store_true")
    p.add_argument("--no-dns",    action="store_true")
    p.add_argument("--no-ports",  action="store_true")
    p.add_argument("--no-tls",    action="store_true")
    p.add_argument("--no-ua",     action="store_true")
    p.add_argument("--no-suspicious", action="store_true")
    args = p.parse_args()

    if not os.path.isfile(args.capture):
        print(f"ERROR: File not found: {args.capture}", file=sys.stderr); sys.exit(1)

    try:
        reader = open_capture(args.capture)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr); sys.exit(1)

    fmt = "PCAPng" if isinstance(reader, PcapngReader) else "PCAP (classic)"
    ifaces = len(reader.interfaces)
    print(f"Reading {os.path.basename(args.capture)}  [{fmt}, {ifaces} interface(s), link-type {reader.link_type}] …",
          file=sys.stderr)

    az = PcapAnalyzer(resolve_rdns=args.resolve)
    try:
        az.process(reader)
    except KeyboardInterrupt:
        print("\n(interrupted — partial results follow)", file=sys.stderr)
    finally:
        reader.close()

    sites  = az.websites_visited(top=args.top, keyword=args.filter)
    summ   = az.summary()

    if args.json:
        out = {
            "meta": {"file": args.capture, "format": fmt},
            "summary": summ,
            "websites_visited": sites,
            "http_requests": [
                {k:v for k,v in r.items() if k != "ts"} for r in az.http_requests[:500]
            ],
            "dns_queries":      dict(az.dns_queries.most_common(200)),
            "dns_resolved":     {k:list(v) for k,v in list(az.dns_answers.items())[:200]},
            "tls_versions":     dict(az.tls_versions),
            "tls_sni_top50":    dict(az.https_sni.most_common(50)),
            "protocol_distribution": dict(az.proto_counts),
            "top_ports":        dict(az.port_counts.most_common(30)),
            "top_external_ips": dict(az.external_ips.most_common(30)),
            "user_agents":      az.top_user_agents(20),
            "suspicious_events": az.suspicious[:100],
        }
        print(json.dumps(out, indent=2))
        return

    print_banner(args.capture, fmt)
    print_summary(summ)
    print_websites(sites)
    print_categories(sites)
    if not args.no_http:  print_http_requests(az.http_requests)
    if not args.no_dns:   print_dns(az.dns_queries, az.dns_answers)
    if not args.no_tls:   print_tls(az.tls_versions, az.https_sni)
    print_protocols(az.proto_counts)
    if not args.no_ports: print_ports(az.port_counts)
    print_ext_ips(az.external_ips, az.dns_ptr, az.dns_answers)
    if not args.no_ua:    print_user_agents(az.top_user_agents())
    if not args.no_suspicious: print_suspicious(az.suspicious)
    print(f"\n{_c('ok','✓ Analysis complete.')}\n")

if __name__ == "__main__":
    main()
