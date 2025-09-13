import asyncio
import json
import os
import re
import time
import base64
import getpass
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse

from playwright.async_api import async_playwright, TimeoutError as PWTimeoutError

CONFIG_PATH = Path("config.json")
SESSION_PATH = Path("session.json")

def _print(msg: str) -> None:
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")

def _safe_json_dump(path: Path, data: Dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding="utf-8")

def _extract_token_from_text(text: str) -> Optional[str]:
    # Look for JSON "token": "<hex...>"
    m = re.search(r'"token"\s*:\s*"([A-Za-z0-9._-]{16,})"', text)
    if m:
        return m.group(1)
    return None

def _extract_token_from_payload(payload: str) -> Optional[str]:
    """Try to extract a token from Socket.IO frames, raw JSON, or base64-encoded JSON."""
    # 0) Socket.IO event frame (e.g., 42["authorization", {"token": "..."}])
    tok = _extract_token_from_socketio(payload)
    if tok:
        return tok

    # 1) Direct JSON
    try:
        obj = json.loads(payload)
        if isinstance(obj, dict):
            tok = obj.get("token")
            if isinstance(tok, str):
                return tok
            # nested
            for key in ("message", "data", "payload"):
                sub = obj.get(key)
                if isinstance(sub, dict) and isinstance(sub.get("token"), str):
                    return sub["token"]
    except Exception:
        pass

    # 2) base64 JSON
    try:
        s = payload.strip()
        if re.fullmatch(r"[A-Za-z0-9_\-+/=]+", s) and len(s) >= 16:
            missing = (-len(s)) % 4
            if missing:
                s += "=" * missing
            decoded = base64.b64decode(s)
            as_text = decoded.decode("utf-8", errors="ignore")
            tok = _extract_token_from_text(as_text)
            if tok:
                return tok
    except Exception:
        pass

    # 3) fallback regex on raw
    return _extract_token_from_text(payload)

def _extract_token_from_socketio(payload: str) -> Optional[str]:
    """Extract token from Socket.IO event frames like:
       42["authorization", {"isDemo": false, "token": "<JWT>"}]
    """
    try:
        # Find the first JSON array in the payload (after any numeric prefix like "42")
        idx = payload.find("[")
        if idx == -1:
            return None
        arr_text = payload[idx:]
        arr = json.loads(arr_text)
        if isinstance(arr, list) and len(arr) >= 2:
            event = arr[0]
            data = arr[1]
            if isinstance(event, str) and isinstance(data, dict):
                # Common event names for auth flows
                if event.lower() in ("authorization", "authorize", "auth", "authenticated"):
                    tok = data.get("token")
                    if isinstance(tok, str) and len(tok) >= 16:
                        return tok
                # If the event name differs, still try to pick a token-like field
                for k, v in data.items():
                    if isinstance(k, str) and "token" in k.lower() and isinstance(v, str) and len(v) >= 16:
                        return v
    except Exception:
        pass
    return None

@dataclass
class Credentials:
    email: str
    password: str

class BinollaBot:
    def __init__(self, creds: Credentials, headless: bool = False):
        self.email = creds.email
        self.password = creds.password
        self.headless = headless
        self.ws_urls: List[str] = []
        self.token: Optional[str] = None

    # persistence
    def save_config(self) -> None:
        """Save ONLY email/password to config.json."""
        _safe_json_dump(CONFIG_PATH, {"email": self.email, "password": self.password})
        _print("Login credentials saved to config.json")

    def save_session(self) -> None:
        """Save ONLY token to session.json."""
        _safe_json_dump(SESSION_PATH, {"token": self.token})
        _print("Session data saved to session.json (token only)")

    # language utilities
    async def _seed_language_preferences(self, context, page) -> None:
        """Prefer English as UI language early on."""
        try:
            await context.add_init_script("""() => {
                try {
                  document.documentElement.setAttribute('lang', 'en');
                  localStorage.setItem('NEXT_LOCALE', 'en');
                  localStorage.setItem('language', 'en');
                  localStorage.setItem('locale', 'en');
                  localStorage.setItem('i18nextLng', 'en');
                  document.cookie = 'NEXT_LOCALE=en; path=/; max-age=31536000; SameSite=Lax';
                } catch (e) {}
            }""")
        except Exception:
            pass

        # Seed cookie for binolla.com
        try:
            await context.add_cookies([{
                "name": "NEXT_LOCALE",
                "value": "en",
                "domain": "binolla.com",
                "path": "/",
                "httpOnly": False,
                "secure": True,
                "sameSite": "Lax",
            }])
            _print("Seeded NEXT_LOCALE cookie for binolla.com")
        except Exception as e:
            _print(f"Cookie seeding warning: {e}")

    async def _ensure_en_dropdown(self, page) -> None:
        """If language dropdown isn't English, switch it to English."""
        try:
            lang_btn = page.locator("#dse-language-change-dropdown-button").first
            await lang_btn.wait_for(state="visible", timeout=5000)
            text = (await lang_btn.inner_text()).strip().lower()
            if "english" not in text:
                await lang_btn.click()
                en_item = page.get_by_role("option", name=re.compile(r"English", re.I))
                if await en_item.count():
                    await en_item.first.click()
                    _print("Language switched to English via dropdown.")
                else:
                    # Fallback: click by text within any dropdown list
                    await page.get_by_text("English", exact=False).first.click(timeout=3000)
                    _print("Language switched to English via text fallback.")
        except Exception:
            # If not present or already English, it's fine.
            pass

    # notifications
    async def _grant_notifications(self, context, origin: str) -> None:
        try:
            await context.grant_permissions(["notifications"], origin=origin)
        except Exception:
            pass

    async def _try_click_allow_ui(self, page) -> None:
        candidates = [
            'button:has-text("Allow")',
            'text=/^Allow Notifications?$/i',
            'button:has-text("السماح")',
            'text=/السماح/',
        ]
        for sel in candidates:
            try:
                loc = page.locator(sel)
                if await loc.count():
                    await loc.first.click(timeout=800)
                    _print('Clicked site "Allow" button.')
                    return
            except Exception:
                continue

    # login flow
    async def _fill_login(self, page) -> None:
        await page.wait_for_load_state("domcontentloaded")

        await self._ensure_en_dropdown(page)

        email_selectors = [
            'input[name="email"]',
            'input[inputmode="email"]',
            'input[type="email"]',
            'input[autocomplete="username"]',
            'input[placeholder*="mail" i]',
        ]
        pass_selectors = [
            'input[name="password"]',
            'input[type="password"]',
            'input[autocomplete="current-password"]',
        ]
        submit_selectors = [
            'button[type="submit"]',
            'button:has-text("Sign In")',
            'button:has-text("Log In")',
            'text=/^Sign In$/i',
        ]

        # Fill email
        for sel in email_selectors:
            try:
                el = page.locator(sel).first
                await el.wait_for(state="visible", timeout=4000)
                await el.fill(self.email, timeout=4000)
                break
            except Exception:
                continue
        else:
            raise RuntimeError("Could not find email field")

        # Fill password
        for sel in pass_selectors:
            try:
                el = page.locator(sel).first
                await el.wait_for(state="visible", timeout=4000)
                await el.fill(self.password, timeout=4000)
                break
            except Exception:
                continue
        else:
            raise RuntimeError("Could not find password field")

        # Click submit
        for sel in submit_selectors:
            try:
                btn = page.locator(sel).first
                if await btn.count():
                    await btn.click(timeout=4000)
                    break
            except Exception:
                continue
        else:
            await page.keyboard.press("Enter")

        _print("Submitted login form.")
        try:
            await page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass

    # token capture
    async def _scan_client_storage_for_token(self, page) -> Optional[str]:
        # Try to read possible tokens from window/localStorage/cookies (non-httpOnly only)
        try:
            token = await page.evaluate("""() => {
                try {
                    // look through localStorage
                    for (let i = 0; i < localStorage.length; i++) {
                        const k = localStorage.key(i);
                        const v = localStorage.getItem(k) || "";
                        if (/token/i.test(k) && typeof v === 'string' && v.length >= 16) return v;
                        const m = /"token"\\s*:\\s*"([A-Za-z0-9._-]{16,})"/.exec(v);
                        if (m) return m[1];
                    }
                    // in-memory globals
                    for (const k of Object.keys(window)) {
                        if (/token/i.test(k)) {
                            const v = String(window[k] ?? '');
                            if (v && v.length >= 16) return v;
                        }
                    }
                    // Try to parse document.cookie (non-httpOnly only)
                    const parts = (document.cookie || '').split(';');
                    for (const p of parts) {
                        const [ck, cv] = p.split('=');
                        if (/token/i.test(ck || '') && (cv || '').length >= 16) return cv;
                    }
                } catch (e) {}
                return null;
            }""")
            if token and isinstance(token, str):
                return token
        except Exception:
            pass
        return None

    # main
    async def run(self) -> None:
        self.save_config()

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=self.headless,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-blink-features=AutomationControlled",
                    "--disable-dev-shm-usage",
                    "--ignore-certificate-errors",
                    "--disable-features=IsolateOrigins,site-per-process",
                ],
            )

            context = await browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/125.0.0.0 Safari/537.36"
                ),
                locale="en-US",
                permissions=["notifications"],
                viewport={"width": 1366, "height": 768},
                extra_http_headers={"Accept-Language": "en-US,en;q=0.9"},
            )
            await context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined});")

            # Pre-seed language
            seed_page = await context.new_page()
            await self._seed_language_preferences(context, seed_page)
            await seed_page.close()

            # Grant notifications
            await self._grant_notifications(context, "https://binolla.com")

            page = await context.new_page()

            # Token event
            token_event = asyncio.Event()

            # Watch responses for tokens
            async def on_response(response):
                try:
                    url = response.url
                    if not url.startswith("http"):
                        return
                    ct = response.headers.get("content-type", "")
                    if "application/json" in ct:
                        text = await response.text()
                        tok = _extract_token_from_text(text)
                        if tok and not self.token:
                            self.token = tok
                            _print(f"Token captured (HTTP): {self.token}")
                            self.save_session()
                            token_event.set()
                except Exception:
                    pass

            page.on("response", on_response)

            # Watch websockets for tokens
            def on_websocket(ws):
                self.ws_urls.append(ws.url)
                _print(f"WebSocket created: {ws.url}")
                # Hint: expecting ws3.binolla.com/socket.io for Binolla

                async def _handle_payload(payload: str):
                    if self.token:
                        return
                    tok = _extract_token_from_payload(payload)
                    if tok:
                        self.token = tok
                        _print(f"Token captured (WS): {self.token}")
                        self.save_session()
                        token_event.set()

                def _frame_received(payload: str):
                    asyncio.create_task(_handle_payload(payload))

                ws.on("framereceived", _frame_received)
                ws.on("framesent", _frame_received)

            page.on("websocket", on_websocket)

            url = "https://binolla.com/login/"
            _print(f"Navigating to {url} ...")
            await page.goto(url, wait_until="domcontentloaded", timeout=60000)

            await self._ensure_en_dropdown(page)
            await self._try_click_allow_ui(page)
            await self._fill_login(page)

            # After submit, wait up to 30s for token via WS/HTTP; otherwise, fallback to scanning storage
            try:
                await asyncio.wait_for(token_event.wait(), timeout=30)
                _print("Token saved. Closing browser now...")
            except asyncio.TimeoutError:
                _print("Token not captured from network within 30s; scanning client storage...")
                tok = await self._scan_client_storage_for_token(page)
                if tok:
                    self.token = tok
                    self.save_session()
                    _print("Token saved from client storage. Closing browser now...")
                else:
                    _print("Token not found. Closing browser.")

            await browser.close()

def prompt_for_credentials(existing_email: str = "", existing_password: str = "") -> Credentials:
    print("\n=== Enter Binolla login credentials (will be saved to config.json) ===")
    while True:
        prompt = f"Email [{existing_email}]: " if existing_email else "Email: "
        entered = input(prompt).strip()
        email = entered or existing_email
        if email:
            break
        print("Email cannot be empty. Please try again.")
    while True:
        pw_prompt = "(input hidden) Password"
        if existing_password:
            pw_prompt += " [press Enter to keep existing]"
        pw_prompt += ": "
        entered_pw = getpass.getpass(pw_prompt)
        password = entered_pw if entered_pw else existing_password
        if password:
            break
        print("Password cannot be empty. Please try again.")
    return Credentials(email=email, password=password)

async def main():
    # Load any existing to show defaults; ALWAYS prompt
    if CONFIG_PATH.exists():
        try:
            cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:
            cfg = {}
        existing_email = cfg.get("email", "")
        existing_password = cfg.get("password", "")
    else:
        existing_email = os.environ.get("BINOLLA_EMAIL", "")
        existing_password = os.environ.get("BINOLLA_PASSWORD", "")

    creds = prompt_for_credentials(existing_email, existing_password)

    bot = BinollaBot(creds, headless=False)
    await bot.run()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
