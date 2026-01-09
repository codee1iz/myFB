import logging
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, render_template, request
from sqlalchemy import asc
from sqlalchemy import event
from sqlalchemy.orm import Session as SASession
from sqlalchemy.orm import sessionmaker

from CTFd.models import Challenges, Configs, Solves, db
from CTFd.plugins import bypass_csrf_protection
from CTFd.utils import get_config, set_config
from CTFd.utils.decorators import admins_only
from CTFd.utils.modes import get_model

log = logging.getLogger(__name__)

# --- Config keys ---
CFG_ENABLED = "FB_TG_ENABLED"          # "1" / "0"
CFG_TOKEN = "FB_TG_TOKEN"              # bot token
CFG_CHAT_ID = "FB_TG_CHAT_ID"          # telegram chat id
CFG_TEMPLATE = "FB_TG_TEMPLATE"        # message template
CFG_PARSE_MODE = "FB_TG_PARSE_MODE"    # "", "HTML", "MarkdownV2"

SessionLocal = None


def _new_session() -> SASession:
    global SessionLocal
    if SessionLocal is None:
        SessionLocal = sessionmaker(bind=db.engine, expire_on_commit=False)
    return SessionLocal()


def _cfg(key: str, default: str = "", session: Optional[SASession] = None) -> str:
    if session is None:
        value = get_config(key)
        if value is None:
            return default
        return str(value)

    value = session.query(Configs.value).filter(Configs.key == key).scalar()
    if value is None:
        return default
    return str(value)


def _is_enabled() -> bool:
    return _cfg(CFG_ENABLED, "0") == "1"


def _mask_token(token: str) -> str:
    token = token.strip()
    if not token:
        return ""
    if len(token) <= 10:
        return "*" * len(token)
    return f"{token[:6]}...{token[-4:]}"


def _normalize_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def _get_settings_payload() -> Dict[str, Any]:
    return {
        "success": True,
        "settings": {
            "enabled": _cfg(CFG_ENABLED, "0") == "1",
            "token_masked": _mask_token(_cfg(CFG_TOKEN, "")),
            "token_is_set": bool(_cfg(CFG_TOKEN, "").strip()),
            "chat_id": _cfg(CFG_CHAT_ID, ""),
            "template": _cfg(CFG_TEMPLATE, "🩸 FIRST BLOOD! {solver} solved {challenge}"),
            "parse_mode": _cfg(CFG_PARSE_MODE, ""),
        },
        "placeholders": [
            "{solver}",
            "{solver_type}",
            "{challenge}",
            "{category}",
            "{points}",
            "{solve_id}",
            "{challenge_id}",
            "{date_utc}",
        ],
    }


def _telegram_send_message(token: str, chat_id: str, text: str, parse_mode: str = "") -> None:
    """
    Minimal Telegram sendMessage without extra deps.
    """
    # Validate inputs
    if not token or not token.strip():
        raise ValueError("Telegram bot token is required")
    if not chat_id or not chat_id.strip():
        raise ValueError("Telegram chat_id is required")
    if not text or not text.strip():
        raise ValueError("Message text is required")
    
    # Clean inputs
    token = token.strip()
    chat_id = chat_id.strip()
    text = text.strip()
    
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text}
    if parse_mode:
        payload["parse_mode"] = parse_mode.strip()

    # Use urlencode with doseq=False to properly encode the payload
    data = urllib.parse.urlencode(payload, doseq=False).encode("utf-8")
    req = urllib.request.Request(
        url, 
        data=data, 
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            response_data = resp.read()
            # Check if response indicates success
            if resp.status != 200:
                log.error(
                    f"FirstBloodTelegram: HTTP {resp.status} response: "
                    f"{response_data.decode('utf-8', errors='ignore')}"
                )
            else:
                log.debug(f"FirstBloodTelegram: message sent successfully to chat_id={chat_id}")
    except urllib.error.HTTPError as e:
        error_body = ""
        try:
            error_body = e.read().decode('utf-8', errors='ignore')
        except Exception:
            pass
        log.error(
            f"FirstBloodTelegram: HTTP {e.code} {e.reason} - "
            f"Chat ID: {chat_id} - Token: {_mask_token(token)} - "
            f"Parse Mode: {parse_mode or '(none)'} - "
            f"Message Length: {len(text)} - "
            f"Response: {error_body}"
        )
        # Don't re-raise - just log the error so it doesn't break the solve
    except Exception as e:
        log.exception(
            f"FirstBloodTelegram: failed to send telegram message - "
            f"Chat ID: {chat_id} - Token: {_mask_token(token)}"
        )
        # Don't re-raise - just log the error so it doesn't break the solve


def _escape_markdown_v2(text: str) -> str:
    """
    Escape special characters for Telegram MarkdownV2 format.
    """
    # Characters that need to be escaped in MarkdownV2
    special_chars = ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']
    escaped = text
    for char in special_chars:
        escaped = escaped.replace(char, '\\' + char)
    return escaped


def _render_template_text(template: str, vars_: Dict[str, str], escape_markdown: bool = False) -> str:
    """
    Simple template rendering: {key} -> value
    
    :param template: Template string with {placeholders}
    :param vars_: Dictionary of placeholder values
    :param escape_markdown: If True, escape special MarkdownV2 characters in the final message
    """
    # First, replace placeholders with values (don't escape values yet)
    rendered = template
    for key, value in vars_.items():
        rendered = rendered.replace("{" + key + "}", value)
    
    # If using MarkdownV2, escape the entire final message
    # This handles special characters in both template text (like '!' in "FIRST BLOOD!")
    # and in variable values (like challenge names, solver names, etc.)
    if escape_markdown:
        rendered = _escape_markdown_v2(rendered)
    
    return rendered


def _first_visible_solve_for_challenge(session, model, challenge_id: int) -> Optional[Solves]:
    """
    First solve per challenge among visible/non-banned accounts.
    """
    query = (
        session.query(Solves)
        .join(model, Solves.account_id == model.id)
        .filter(Solves.challenge_id == challenge_id, model.hidden == False, model.banned == False)
        .order_by(asc(Solves.date), asc(Solves.id))
    )
    return query.first()


def _announce_first_blood_if_needed(session: SASession, solve_id: int) -> None:
    log.debug(f"FirstBloodTelegram: checking if announcement needed for solve_id={solve_id}")
    
    if _cfg(CFG_ENABLED, "0", session=session) != "1":
        log.debug(f"FirstBloodTelegram: plugin disabled for solve_id={solve_id}")
        return

    token = _cfg(CFG_TOKEN, "", session=session).strip()
    chat_id = _cfg(CFG_CHAT_ID, "", session=session).strip()
    if not token or not chat_id:
        log.warning(
            f"FirstBloodTelegram: token or chat_id not configured for solve_id={solve_id} - "
            f"token_set={bool(token)}, chat_id_set={bool(chat_id)}"
        )
        return

    solve = session.get(Solves, solve_id)
    if not solve:
        log.warning(f"FirstBloodTelegram: solve_id={solve_id} not found in database")
        return

    model = get_model()
    account = session.get(model, solve.account_id)
    if not account:
        log.debug(f"FirstBloodTelegram: account not found for solve_id={solve_id}, account_id={solve.account_id}")
        return
    
    if getattr(account, "hidden", False):
        log.debug(f"FirstBloodTelegram: account is hidden for solve_id={solve_id}, account_id={solve.account_id}")
        return
    
    if getattr(account, "banned", False):
        log.debug(f"FirstBloodTelegram: account is banned for solve_id={solve_id}, account_id={solve.account_id}")
        return

    challenge_id = getattr(solve, "challenge_id", None)
    if not challenge_id:
        log.warning(f"FirstBloodTelegram: challenge_id not found for solve_id={solve_id}")
        return

    first = _first_visible_solve_for_challenge(session, model, int(challenge_id))
    if not first:
        log.debug(f"FirstBloodTelegram: no first solve found for challenge_id={challenge_id}, solve_id={solve_id}")
        return
    
    if int(first.id) != int(solve.id):
        log.debug(
            f"FirstBloodTelegram: not first blood - first solve_id={first.id}, current solve_id={solve.id}, "
            f"challenge_id={challenge_id}"
        )
        return

    challenge = session.get(Challenges, int(challenge_id))
    challenge_name = str(getattr(challenge, "name", "") or f"challenge:{challenge_id}")
    challenge_category = str(getattr(challenge, "category", "") or "")
    challenge_points = str(getattr(challenge, "value", "") or "")

    solver_name = str(getattr(account, "name", "") or f"account:{solve.account_id}")
    solver_type = "team" if model.__name__.lower().startswith("team") else "user"

    vars_ = {
        "solver": solver_name,
        "solver_type": solver_type,
        "challenge": challenge_name,
        "category": challenge_category,
        "points": challenge_points,
        "solve_id": str(solve.id),
        "challenge_id": str(challenge_id),
        "date_utc": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    }

    template = _cfg(
        CFG_TEMPLATE,
        "🩸 FIRST BLOOD! {solver} solved {challenge}",
        session=session,
    )
    parse_mode = _cfg(CFG_PARSE_MODE, "", session=session).strip()
    
    # Escape MarkdownV2 special characters if using MarkdownV2
    escape_markdown = (parse_mode == "MarkdownV2")
    message = _render_template_text(template, vars_, escape_markdown=escape_markdown)

    log.info(
        f"FirstBloodTelegram: sending first blood announcement - "
        f"solve_id={solve_id}, challenge={challenge_name}, solver={solver_name}, "
        f"chat_id={chat_id}, message_length={len(message)}, parse_mode={parse_mode or '(none)'}"
    )
    _telegram_send_message(token=token, chat_id=chat_id, text=message, parse_mode=parse_mode)


def load(app):
    """
    Entry point for CTFd plugin.
    """

    bp = Blueprint(
        "first_blood_telegram",
        __name__,
        url_prefix="/admin/first_blood_telegram",
        template_folder="templates",
        static_folder="assets",
        static_url_path="/plugins/first_blood_telegram/assets",
    )

    @bp.route("/", methods=["GET"])
    @admins_only
    def get_settings():
        """
        Return plugin settings as JSON or render HTML.
        """
        wants_json = False
        if request.args.get("format") == "json":
            wants_json = True
        else:
            best = request.accept_mimetypes.best_match(["application/json", "text/html"])
            if best == "application/json":
                wants_json = (
                    request.accept_mimetypes[best]
                    > request.accept_mimetypes["text/html"]
                )

        payload = _get_settings_payload()
        if wants_json:
            payload["how_to_update"] = {
                "method": "POST",
                "content_type": "application/json",
                "body_example": {
                    "enabled": True,
                    "token": "123456:ABCDEF...",
                    "chat_id": "-1001234567890",
                    "template": "🏁 FB! {solver} первым закрыл «{challenge}»",
                    "parse_mode": "",
                },
            }
            return jsonify(payload)

        return render_template(
            "first_blood_telegram/admin.html",
            settings=payload["settings"],
            placeholders=payload["placeholders"],
        )

    @bp.route("/", methods=["POST"])
    @admins_only
    @bypass_csrf_protection
    def set_settings():
        """
        Update plugin settings.
        """
        payload: Dict[str, Any] = {}
        if request.is_json:
            payload = request.get_json(silent=True) or {}
        else:
            payload = dict(request.form)

        allowed_parse_modes = {"", "HTML", "MarkdownV2"}

        if "parse_mode" in payload:
            parse_mode = str(payload["parse_mode"]).strip()
            if parse_mode not in allowed_parse_modes:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "parse_mode must be one of '', 'HTML', 'MarkdownV2'",
                        }
                    ),
                    400,
                )
            set_config(CFG_PARSE_MODE, parse_mode)

        if "enabled" in payload:
            enabled = _normalize_bool(payload["enabled"])
            set_config(CFG_ENABLED, "1" if enabled else "0")

        clear_token = _normalize_bool(payload.get("clear_token", False))
        if clear_token:
            set_config(CFG_TOKEN, "")
        elif "token" in payload:
            token_value = str(payload["token"]).strip()
            if token_value:
                set_config(CFG_TOKEN, token_value)

        if "chat_id" in payload:
            set_config(CFG_CHAT_ID, str(payload["chat_id"]).strip())

        if "template" in payload:
            template = str(payload["template"]).strip()
            set_config(CFG_TEMPLATE, template or "🩸 FIRST BLOOD! {solver} solved {challenge}")

        return jsonify({"success": True})

    @bp.route("/test", methods=["POST"])
    @admins_only
    @bypass_csrf_protection
    def test_message():
        """
        Send a test message to current chat_id.
        """
        token = _cfg(CFG_TOKEN, "").strip()
        chat_id = _cfg(CFG_CHAT_ID, "").strip()
        if not token or not chat_id:
            return jsonify({"success": False, "error": "token/chat_id not set"}), 400

        message = "✅ FirstBloodTelegram test message"
        _telegram_send_message(
            token=token,
            chat_id=chat_id,
            text=message,
            parse_mode=_cfg(CFG_PARSE_MODE, "").strip(),
        )
        return jsonify({"success": True})

    app.register_blueprint(bp)

    @event.listens_for(db.session, "after_flush")
    def _after_flush(session, flush_context):
        pending = session.info.setdefault("fb_tg_pending_solves", [])
        for obj in session.new:
            if isinstance(obj, Solves):
                solve_id = getattr(obj, "id", None)
                if solve_id is not None:
                    pending.append(int(solve_id))
                    log.debug(f"FirstBloodTelegram: queued solve_id={solve_id} for announcement")

    @event.listens_for(db.session, "after_rollback")
    def _after_rollback(session):
        session.info.pop("fb_tg_pending_solves", None)

    @event.listens_for(db.session, "after_commit")
    def _after_commit(session):
        solve_ids = session.info.pop("fb_tg_pending_solves", [])
        if not solve_ids:
            return
        
        # Don't check _is_enabled() here because it uses get_config() which requires
        # an active session, but we're in 'committed' state. Check it inside the new session.
        with app.app_context():
            new_session = _new_session()
            try:
                # Check if plugin is enabled using the new session
                if _cfg(CFG_ENABLED, "0", session=new_session) != "1":
                    log.debug(f"FirstBloodTelegram: plugin disabled, skipping {len(solve_ids)} solve(s)")
                    return
                
                for solve_id in solve_ids:
                    try:
                        log.debug(f"FirstBloodTelegram: processing solve_id={solve_id}")
                        _announce_first_blood_if_needed(new_session, solve_id)
                    except Exception as e:
                        log.exception(
                            f"FirstBloodTelegram: failed to announce for solve_id={solve_id}: {e}"
                        )
            finally:
                new_session.close()
