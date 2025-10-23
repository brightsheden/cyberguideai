import re
from urllib.parse import urlparse


def analyze_link(url: str) -> dict:
    """
    Passive heuristics to flag suspicious links. Returns a dictionary with
    warnings and evidence. This is NOT an active scanner — only string-based
    heuristics safe to run anywhere.

    Output shape:
    {
        "url": str,
        "suspicious": bool,
        "reasons": [str],
        "components": {"scheme":..., "host":..., "path":..., "query":...}
    }
    """
    if not url or not isinstance(url, str):
        return {"url": url, "suspicious": False, "reasons": ["no input"], "components": {}}

    url = url.strip()
    parsed = urlparse(url if re.match(r'^https?://', url) else 'http://' + url)
    host = parsed.hostname or ''
    reasons = []

    # Suspicious patterns
    if parsed.scheme not in ('http', 'https'):
        reasons.append(f"unusual-scheme:{parsed.scheme}")

    # Punycode domains (xn--)
    if host.startswith('xn--'):
        reasons.append('punycode-domain')

    # IP address instead of hostname
    if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', host):
        reasons.append('ip-in-host')

    # Long hostnames or many subdomains
    if host.count('.') >= 5:
        reasons.append('many-subdomains')

    # Look for @ in the path (obfuscation like user@host)
    if '@' in parsed.path:
        reasons.append('at-in-path')

    # Suspicious TLDs list (minimal example)
    suspicious_tlds = ('.tk', '.ml', '.ga', '.cf', '.gq')
    for tld in suspicious_tlds:
        if host.endswith(tld):
            reasons.append('suspicious-tld')
            break

    # Many URL-encoded characters
    pct_encoded = parsed.path.count('%') + (parsed.query.count('%') if parsed.query else 0)
    if pct_encoded > 5:
        reasons.append('many-percent-encodings')

    # Homograph lookups: repeated characters or hyphen tricks
    if re.search(r'[-]{2,}', host) or re.search(r'[^a-z0-9.-]', host, re.I):
        reasons.append('weird-host-chars')

    suspicious = len(reasons) > 0

    return {
        "url": url,
        "suspicious": suspicious,
        "reasons": reasons,
        "components": {"scheme": parsed.scheme, "host": host, "path": parsed.path, "query": parsed.query}
    }


def analyze_email(headers: dict, body: str) -> dict:
    """
    Passive heuristics for email phishing analysis.
    - headers: dict-like (must include 'From', 'Reply-To', 'Return-Path', 'Received') where available
    - body: full email body as plain text or HTML

    Returns a dict with warnings and extracted links.
    """
    reasons = []
    links = []

    # Basic header checks
    from_hdr = (headers.get('From') or '') if headers else ''
    reply_to = (headers.get('Reply-To') or '') if headers else ''
    # return_path not used currently but may be useful in future checks
    _return_path = (headers.get('Return-Path') or '') if headers else ''

    if from_hdr and '<' in from_hdr and '>' in from_hdr:
        # parse email address inside <>
        m = re.search(r'<([^>]+)>', from_hdr)
        if m:
            addr = m.group(1)
            if addr.lower().endswith('@example.com') and 'trusted' not in from_hdr.lower():
                reasons.append('display-name-mismatch')

    # Reply-to differs from from -> suspicious
    if reply_to and from_hdr and reply_to not in from_hdr:
        reasons.append('reply-to-differs')

    # Simple body link extraction (http:// or https:// and bare domains)
    for m in re.finditer(r'(https?://[^\s"<>]+)', body or '', re.I):
        url = m.group(1).rstrip('.,)')
        links.append(url)

    # If no https links at all and there are links, consider suspicious
    if links and not any(u.startswith('https://') for u in links):
        reasons.append('no-https-links')

    # If body contains typical phishing words
    phishing_words = ['verify your account', 'update your password', 'confirm your identity', 'click below']
    lowered = (body or '').lower()
    for w in phishing_words:
        if w in lowered:
            reasons.append(f'keyword:{w}')

    # run per-link analysis
    analyzed_links = [analyze_link(u) for u in links]

    suspicious = len(reasons) > 0 or any(item['suspicious'] for item in analyzed_links)

    return {
        'suspicious': suspicious,
        'reasons': reasons,
        'links': analyzed_links,
    }
