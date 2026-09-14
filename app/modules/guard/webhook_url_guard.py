"""
SSRF guard for tenant-supplied webhook URLs.

2026-09-14 audit follow-up: POST /tenants/my-apps/{app_source}/webhook only
ever validated `url.startswith("https://")` -- no check against internal/
private IP ranges. Low real-world severity on Vercel specifically (a
serverless function has no internal network belonging to the tenant to
reach -- there's no "10.0.0.5" of theirs sitting next to this process the
way there would be in a traditional on-prem SSRF scenario), but it was a
disclosed, unmitigated gap, not a closed one: an attacker who can get a
domain to resolve to 169.254.169.254 (a cloud metadata endpoint -- AWS/GCP/
Azure all use it, and it's real infrastructure this app's own dependencies
touch even if Vercel's own request path doesn't) or to a Supabase-internal
address gets this app's own server to make an authenticated-looking POST
to it, blind, on every governance decision for that app_source.

Two checks are deliberately separate, not one:
  1. validate_webhook_url() -- run once at registration time
     (POST/PUT .../webhook). Rejects loudly with a 400 the customer sees.
  2. is_still_safe_to_deliver() -- run again immediately before EVERY
     delivery attempt (both the synchronous one in _deliver_webhook and
     each retry in process_webhook_retries). A URL that resolved to a
     public IP at registration can be repointed via DNS *after* that check
     passed (classic TOCTOU/DNS-rebinding) -- re-resolving right before
     connecting closes that window down to the time between this check and
     aiohttp's own connect, not the time between registration and
     delivery (which could be days). Fails silently (treated as a normal
     delivery failure, queued for retry like any other) rather than
     raising, since delivery code paths must never break the governance
     decision itself.
"""

import ipaddress
import logging
import socket
from typing import Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("cgc.guard.webhook_url")


def _is_unsafe_ip(ip_str: str) -> bool:
    """True if this address must never be connected to on the tenant's
    behalf -- private/RFC1918, loopback, link-local (covers the
    169.254.169.254 cloud metadata endpoint), multicast, reserved, or
    unspecified. Deliberately broad: the cost of over-blocking a
    legitimate-but-unusual public webhook target is a support ticket; the
    cost of under-blocking is a blind SSRF primitive."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # not a parseable IP at all -- treat as unsafe, don't guess
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _resolve_all(hostname: str) -> list:
    """Blocking DNS resolution -- callers on the event loop must run this
    via run_in_executor. Returns every resolved IP (A + AAAA), not just
    the first, since an attacker only needs ONE of them to be internal."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise ValueError(f"could not resolve hostname: {e}")
    return sorted({info[4][0] for info in infos})


def validate_webhook_url(url: str) -> Tuple[bool, Optional[str]]:
    """Full validation for webhook REGISTRATION (POST/PUT .../webhook).
    Blocking (does a real DNS lookup) -- fine to call directly from a sync
    context or awaited via run_in_executor from an async handler; it's a
    one-time check on a low-traffic admin endpoint, not the hot path.
    Returns (True, None) if safe, (False, reason) otherwise."""
    if not url.startswith("https://"):
        return False, "Webhook URL must be https://"

    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return False, "Webhook URL has no resolvable host"

    try:
        ips = _resolve_all(hostname)
    except ValueError as e:
        return False, str(e)

    if not ips:
        return False, "Webhook hostname did not resolve to any address"

    unsafe = [ip for ip in ips if _is_unsafe_ip(ip)]
    if unsafe:
        logger.warning(f"[webhook_guard] rejected registration: {hostname} resolves to internal/reserved {unsafe}")
        return False, "Webhook URL resolves to a private, loopback, or reserved address"

    return True, None


async def is_still_safe_to_deliver(url: str, loop) -> bool:
    """Re-check for DNS rebinding, called immediately before every actual
    delivery attempt. Async (awaited from _deliver_webhook / the retry
    processor's own async context), non-raising -- any failure here
    (resolution error, internal IP found) just means "don't deliver this
    time", handled by the caller exactly like an HTTP failure would be."""
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not parsed.scheme == "https" or not hostname:
        return False
    try:
        ips = await loop.run_in_executor(None, _resolve_all, hostname)
    except ValueError:
        return False
    if not ips or any(_is_unsafe_ip(ip) for ip in ips):
        logger.warning(f"[webhook_guard] blocked delivery: {hostname} now resolves to an unsafe address")
        return False
    return True
