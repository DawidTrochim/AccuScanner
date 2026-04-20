from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urljoin, urlparse


class BrowserDiscoveryUnavailable(RuntimeError):
    """Raised when browser-assisted discovery cannot run in the local environment."""


@dataclass(slots=True)
class BrowserSurface:
    kind: str
    value: str


_TRACK_REQUESTS_SCRIPT = """
(() => {
  if (window.__accuScannerInstalled) {
    return;
  }
  window.__accuScannerInstalled = true;
  window.__accuScannerRequests = [];

  const record = (value) => {
    try {
      if (!value) return;
      window.__accuScannerRequests.push(String(value));
    } catch (error) {
      // Best effort only.
    }
  };

  const originalFetch = window.fetch;
  if (originalFetch) {
    window.fetch = function(input, init) {
      if (typeof input === "string") {
        record(input);
      } else if (input && input.url) {
        record(input.url);
      }
      return originalFetch.call(this, input, init);
    };
  }

  const originalOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url) {
    record(url);
    return originalOpen.apply(this, arguments);
  };
})();
"""


def discover_browser_surface(
    base_url: str,
    *,
    max_pages: int = 5,
    timeout_ms: int = 8000,
    max_clicks: int = 6,
    extra_headers: dict[str, str] | None = None,
) -> list[BrowserSurface]:
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise BrowserDiscoveryUnavailable(
            "Playwright is not installed. Install it with `pip install playwright` "
            "and fetch a browser with `python -m playwright install chromium`."
        ) from exc

    base_netloc = urlparse(base_url).netloc
    discoveries: list[BrowserSurface] = []
    seen: set[tuple[str, str]] = set()
    queue: list[str] = [base_url]
    visited: set[str] = set()

    def add(kind: str, value: str) -> None:
        normalized = _normalize_same_host_url(value, base_url, base_netloc) if kind not in {"query_parameter", "form_field"} else value.strip().lower()
        if not normalized:
            return
        key = (kind, normalized)
        if key in seen:
            return
        seen.add(key)
        discoveries.append(BrowserSurface(kind=kind, value=normalized))

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        header_map = dict(extra_headers or {})
        cookie_header = header_map.pop("Cookie", header_map.pop("cookie", ""))
        if header_map:
            context.set_extra_http_headers(header_map)
        if cookie_header:
            cookies = _cookies_from_header(cookie_header, base_url)
            if cookies:
                context.add_cookies(cookies)
        context.add_init_script(_TRACK_REQUESTS_SCRIPT)
        page = context.new_page()
        page.set_default_navigation_timeout(timeout_ms)
        page.set_default_timeout(timeout_ms)

        while queue and len(visited) < max_pages:
            current_url = queue.pop(0)
            normalized_current = _normalize_same_host_url(current_url, base_url, base_netloc)
            if not normalized_current or normalized_current in visited:
                continue
            visited.add(normalized_current)
            _navigate(page, current_url, timeout_ms, PlaywrightTimeoutError)
            current_page_url = _normalize_same_host_url(page.url, base_url, base_netloc)
            if not current_page_url:
                continue
            add("page", current_page_url)

            for link in _safe_eval(page, "Array.from(document.querySelectorAll('a[href], area[href]')).map(el => el.href)") or []:
                normalized_link = _normalize_same_host_url(link, current_page_url, base_netloc)
                if not normalized_link:
                    continue
                add("page", normalized_link)
                for parameter_name, _ in parse_qsl(urlparse(normalized_link).query, keep_blank_values=True):
                    if parameter_name:
                        add("query_parameter", parameter_name)
                if normalized_link not in visited and normalized_link not in queue and len(visited) + len(queue) < max_pages:
                    queue.append(normalized_link)

            for script_url in _safe_eval(page, "Array.from(document.querySelectorAll('script[src]')).map(el => el.src)") or []:
                add("script_asset", script_url)

            form_entries = _safe_eval(
                page,
                """
                Array.from(document.forms).map(form => ({
                  action: form.action || window.location.href,
                  method: (form.method || 'get').toUpperCase(),
                  fields: Array.from(form.elements)
                    .map(el => (el.name || '').trim())
                    .filter(Boolean),
                  hasFileUpload: Array.from(form.elements).some(el => el.type && el.type.toLowerCase() === 'file')
                }))
                """,
            ) or []
            for form_entry in form_entries:
                action = form_entry.get("action") or current_page_url
                add("form_action", action)
                for field_name in form_entry.get("fields") or []:
                    add("form_field", field_name)

            for endpoint_url in _safe_eval(page, "Array.from(new Set(window.__accuScannerRequests || []))") or []:
                normalized_endpoint = _normalize_same_host_url(endpoint_url, current_page_url, base_netloc)
                if not normalized_endpoint:
                    continue
                add("script_endpoint", normalized_endpoint)
                for parameter_name, _ in parse_qsl(urlparse(normalized_endpoint).query, keep_blank_values=True):
                    if parameter_name:
                        add("query_parameter", parameter_name)

            for resource_url in _safe_eval(page, "performance.getEntriesByType('resource').map(entry => entry.name)") or []:
                normalized_resource = _normalize_same_host_url(resource_url, current_page_url, base_netloc)
                if not normalized_resource:
                    continue
                if normalized_resource.endswith(".js"):
                    add("script_asset", normalized_resource)
                elif any(normalized_resource.endswith(ext) for ext in (".json", ".xml")):
                    add("script_endpoint", normalized_resource)

            for navigated_url in _discover_click_routes(page, current_page_url, base_netloc, timeout_ms, max_clicks, PlaywrightError, PlaywrightTimeoutError):
                add("page", navigated_url)
                if navigated_url not in visited and navigated_url not in queue and len(visited) + len(queue) < max_pages:
                    queue.append(navigated_url)

        context.close()
        browser.close()

    return discoveries


def _navigate(page, url: str, timeout_ms: int, timeout_error_type) -> None:
    try:
        page.goto(url, wait_until="networkidle", timeout=timeout_ms)
    except timeout_error_type:
        page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)


def _safe_eval(page, expression: str):
    try:
        return page.evaluate(f"() => ({expression})")
    except Exception:
        return None


def _discover_click_routes(page, current_url: str, base_netloc: str, timeout_ms: int, max_clicks: int, playwright_error_type, timeout_error_type) -> list[str]:
    discovered: list[str] = []
    elements = page.locator("a[href], button, [role='button'], [onclick]")
    try:
        count = min(elements.count(), max_clicks)
    except Exception:
        return discovered

    for index in range(count):
        restore_failed = False
        try:
            before = page.url
            element = elements.nth(index)
            metadata = element.evaluate(
                """el => ({
                    href: el.href || '',
                    tag: (el.tagName || '').toLowerCase(),
                    type: (el.type || '').toLowerCase(),
                    role: (el.getAttribute('role') || '').toLowerCase(),
                    onclick: !!el.getAttribute('onclick')
                })"""
            )
            href = (metadata or {}).get("href") or ""
            if href.startswith(("mailto:", "tel:", "javascript:")):
                continue
            if (metadata or {}).get("tag") == "button" and (metadata or {}).get("type") in {"submit", "reset"}:
                continue
            element.click(timeout=min(timeout_ms, 2500))
            try:
                page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 2500))
            except timeout_error_type:
                page.wait_for_timeout(350)
            after = _normalize_same_host_url(page.url, current_url, base_netloc)
            if after and after != _normalize_same_host_url(before, current_url, base_netloc) and after not in discovered:
                discovered.append(after)
        except playwright_error_type:
            continue
        finally:
            current_normalized = _normalize_same_host_url(page.url, current_url, base_netloc)
            if current_normalized != _normalize_same_host_url(current_url, current_url, base_netloc):
                try:
                    _navigate(page, current_url, timeout_ms, timeout_error_type)
                except Exception:
                    restore_failed = True
        if restore_failed:
            break
    return discovered


def _normalize_same_host_url(raw_value: str, base_url: str, base_netloc: str) -> str:
    if not raw_value:
        return ""
    normalized = urljoin(base_url, raw_value)
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or parsed.netloc != base_netloc:
        return ""
    return parsed._replace(fragment="").geturl()


def _cookies_from_header(cookie_header: str, base_url: str) -> list[dict[str, str]]:
    parsed = urlparse(base_url)
    cookies: list[dict[str, str]] = []
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            continue
        cookies.append(
            {
                "name": name,
                "value": value,
                "domain": parsed.hostname or "",
                "path": "/",
                "secure": parsed.scheme == "https",
            }
        )
    return cookies
