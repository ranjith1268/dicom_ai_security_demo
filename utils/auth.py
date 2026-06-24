"""Simple session login for the DICOM security demo."""

from __future__ import annotations

import os

import streamlit as st

from utils.embedded_risk_module import log_breach_event


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


def is_authenticated() -> bool:
    return bool(st.session_state.get("authenticated"))


def logout() -> None:
    st.session_state.authenticated = False
    st.session_state.username = None


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
    if is_authenticated():
        return

    st.title("🔐 DICOM Security Demo — Login")
    _render_login_form()
    st.info(
        "Local default: username `admin`, password `demo123`. "
        "Override via `.streamlit/secrets.toml` or `DEMO_APP_USERNAME` / `DEMO_APP_PASSWORD`."
    )
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
