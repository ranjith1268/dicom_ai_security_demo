"""Simple session login for the DICOM security demo."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timedelta

import streamlit as st

try:
    from extra_streamlit_components import CookieManager

    _COOKIES_AVAILABLE = True
except ImportError:
    CookieManager = None  # type: ignore[misc, assignment]
    _COOKIES_AVAILABLE = False

from utils.embedded_risk_module import log_breach_event

COOKIE_NAME = "dicom_demo_auth"
COOKIE_DAYS = 7


def _auth_secret() -> bytes:
    try:
        return str(st.secrets["auth_secret"]).encode("utf-8")
    except (KeyError, FileNotFoundError, AttributeError, TypeError):
        return os.environ.get("DEMO_AUTH_SECRET", "dicom-demo-local-secret").encode("utf-8")


def _credentials() -> tuple[str, str]:
    """Load username/password from Streamlit secrets or environment."""
    try:
        creds = st.secrets["credentials"]
        return str(creds["username"]), str(creds["password"])
    except (KeyError, FileNotFoundError, AttributeError):
        pass

    user = os.environ.get("DEMO_APP_USERNAME", "admin")
    password = os.environ.get("DEMO_APP_PASSWORD", "demo123")
    return user, password


def _validate(username: str, password: str) -> bool:
    expected_user, expected_pass = _credentials()
    return username == expected_user and password == expected_pass


def _cookie_manager():
    """Return CookieManager singleton (must not use @st.cache_resource — it creates widgets)."""
    if not _COOKIES_AVAILABLE:
        return None
    if "dicom_demo_cookie_manager" not in st.session_state:
        st.session_state.dicom_demo_cookie_manager = CookieManager(key="dicom_demo_cookies")
    return st.session_state.dicom_demo_cookie_manager


def _make_token(username: str) -> str:
    payload = json.dumps(
        {"user": username, "exp": int(time.time()) + COOKIE_DAYS * 86400},
        separators=(",", ":"),
    )
    signature = hmac.new(_auth_secret(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


def _verify_token(token: str) -> str | None:
    if not token or "." not in token:
        return None
    payload, signature = token.rsplit(".", 1)
    expected = hmac.new(_auth_secret(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return None
    if int(data.get("exp", 0)) < int(time.time()):
        return None
    user = str(data.get("user", "")).strip()
    return user or None


def _restore_session_from_cookie() -> None:
    if st.session_state.get("authenticated") or not _COOKIES_AVAILABLE:
        return
    cm = _cookie_manager()
    if cm is None:
        return
    token = cm.get(COOKIE_NAME)
    username = _verify_token(token) if token else None
    if username:
        st.session_state.authenticated = True
        st.session_state.username = username


def _set_auth_cookie(username: str) -> None:
    if not _COOKIES_AVAILABLE:
        return
    cm = _cookie_manager()
    if cm is None:
        return
    expires = datetime.now() + timedelta(days=COOKIE_DAYS)
    cm.set(COOKIE_NAME, _make_token(username), expires_at=expires)


def _clear_auth_cookie() -> None:
    if not _COOKIES_AVAILABLE:
        return
    cm = _cookie_manager()
    if cm is not None:
        cm.delete(COOKIE_NAME)


def is_authenticated() -> bool:
    return bool(st.session_state.get("authenticated"))


def logout() -> None:
    st.session_state.authenticated = False
    st.session_state.username = None
    _clear_auth_cookie()


def _render_login_form() -> None:
    st.markdown("### Sign in")
    st.caption("Access is restricted to authorized users for this security demonstration.")

    with st.form("login_form", clear_on_submit=False):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login", type="primary", width="stretch")

    if submitted:
        if _validate(username.strip(), password):
            st.session_state.authenticated = True
            st.session_state.username = username.strip()
            _set_auth_cookie(username.strip())
            log_breach_event(
                action="User Login",
                data_type="authentication",
                data_accessed=f"Successful login: {username.strip()}",
                severity="MEDIUM",
                endpoint="login_form",
            )
            st.rerun()
        else:
            log_breach_event(
                action="Failed Login Attempt",
                data_type="authentication",
                data_accessed=f"Invalid credentials for username: {username.strip() or '(empty)'}",
                severity="HIGH",
                endpoint="login_form",
            )
            st.error("Invalid username or password.")


def require_login() -> None:
    """Block the app until the user signs in."""
    _restore_session_from_cookie()

    if is_authenticated():
        return

    st.title("🔐 DICOM Security Demo — Login")
    _render_login_form()
    st.stop()


def render_user_bar() -> None:
    """Show logged-in user and logout in the sidebar."""
    with st.sidebar:
        st.markdown("---")
        name = st.session_state.get("username", "user")
        st.caption(f"Signed in as **{name}**")
        if st.button("Logout", width="stretch"):
            log_breach_event(
                action="User Logout",
                data_type="authentication",
                data_accessed=f"Session ended for {name}",
                severity="MEDIUM",
                endpoint="login_form",
            )
            logout()
            st.rerun()
