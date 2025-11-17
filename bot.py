#!/usr/bin/env python3
"""
bot.py — LXMFy ↔ n8n Webhook Bridge Bot

Basado en el proyecto “ollama-bot” de LXMFy:
  https://github.com/lxmfy/ollama-bot

Este bot ha sido adaptado y reescrito para actuar como puente sencillo entre
LXMF (a través de LXMFy) y un webhook HTTP de n8n. Toda la lógica “lista”
(respuestas, saludos, RAG, etc.) vive en n8n, mientras que este bot se limita a:

- Escuchar mensajes LXMF y anuncios (announces) en la red Reticulum/LXMF.
- Enviar los eventos a un webhook de n8n en formato JSON.
- Si n8n devuelve un campo "reply", responder por LXMF al remitente.

El código se ha desarrollado con asistencia de IA para la estructura general,
plantilla de bot, manejo de eventos y la integración con n8n.
"""

import argparse
import json
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv
import RNS
from lxmfy import (
    IconAppearance,
    LXMFBot,
    pack_icon_appearance_field,
)
from lxmfy.events import EventPriority


# ---------------------------------------------------------------------------
# Argumentos y entorno
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(description="LXMFy → n8n Webhook Bot")
    parser.add_argument("--env", type=str, help="Path to .env file")
    parser.add_argument("--name", type=str, help="Bot name (overrides BOT_NAME)")
    parser.add_argument(
        "--webhook-url",
        type=str,
        help="n8n Webhook URL (overrides WEBHOOK_URL env var)",
    )
    parser.add_argument(
        "--admins",
        type=str,
        help="Comma-separated list of admin LXMF hashes",
    )
    return parser.parse_args()


args = parse_args()

# Cargar .env
if args.env:
    load_dotenv(args.env)
else:
    load_dotenv()

BOT_NAME = args.name or os.getenv("BOT_NAME", "WebhookBot")

WEBHOOK_URL = args.webhook_url or os.getenv("WEBHOOK_URL")
if not WEBHOOK_URL:
    raise RuntimeError("WEBHOOK_URL is required (env var or --webhook-url)")

WEBHOOK_TIMEOUT = int(os.getenv("WEBHOOK_TIMEOUT", "300"))

LXMF_ADMINS = (
    set(filter(None, args.admins.split(",")))
    if args.admins
    else set(filter(None, os.getenv("LXMF_ADMINS", "").split(",")))
)

SIGNATURE_VERIFICATION_ENABLED = (
    os.getenv("SIGNATURE_VERIFICATION_ENABLED", "false").lower() == "true"
)
REQUIRE_MESSAGE_SIGNATURES = (
    os.getenv("REQUIRE_MESSAGE_SIGNATURES", "false").lower() == "true"
)

BOT_ICON = os.getenv("BOT_ICON", "robot")
ICON_FG_COLOR = os.getenv("ICON_FG_COLOR", "ffffff")
ICON_BG_COLOR = os.getenv("ICON_BG_COLOR", "2563eb")
BOT_OPERATOR = os.getenv("BOT_OPERATOR", "Anonymous Operator")


def _parse_int(value: str | None, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}

ANNOUNCE_INTERVAL = _parse_int(
    os.getenv("ANNOUNCE_INTERVAL") or os.getenv("announce"),
    600,
)
ANNOUNCE_ENABLED = _parse_bool(
    os.getenv("ANNOUNCE_ENABLED") or os.getenv("announce_enabled"),
    True,
)
ANNOUNCE_IMMEDIATELY = _parse_bool(
    os.getenv("ANNOUNCE_IMMEDIATELY")
    or os.getenv("announce_immediately"),
    True,
)

DEBUG_WEBHOOK = _parse_bool(os.getenv("DEBUG_WEBHOOK"), False)

# Paths used to persist identity and LXMF storage. These match the docker-compose
# bind mounts by default but can be overridden via env vars if needed.
DEFAULT_IDENTITY_PATH = "/bot/identity"
DEFAULT_LXMF_STORAGE_PATH = "/bot/lxmf_storage"

_RNS_STORAGE_ROOT = Path(os.path.expanduser("~/.reticulum")) / "storage"
_RNS_IDENTITY_DIR = _RNS_STORAGE_ROOT / "identities"
_RNS_LXMF_DIR = _RNS_STORAGE_ROOT / "lxmf"

IDENTITY_PATH = (
    os.getenv("LXMFBOT_IDENTITY_PATH")
    or os.getenv("BOT_IDENTITY_PATH")
    or os.getenv("IDENTITY_PATH")
    or DEFAULT_IDENTITY_PATH
)

LXMF_STORAGE_PATH = (
    os.getenv("LXMF_STORAGE_PATH")
    or os.getenv("BOT_LXMF_STORAGE_PATH")
    or DEFAULT_LXMF_STORAGE_PATH
)


def _ensure_directory(path: str | None):
    if path:
        os.makedirs(path, exist_ok=True)


_ensure_directory(IDENTITY_PATH)
_ensure_directory(LXMF_STORAGE_PATH)


def _redirect_rns_storage(default_path: Path, desired_path: str | None, label: str):
    """Point RNS/LXMF internal directories to our bind-mounted paths."""

    if not desired_path:
        return

    desired = Path(desired_path).expanduser()
    default = default_path.expanduser()

    desired.mkdir(parents=True, exist_ok=True)
    default.parent.mkdir(parents=True, exist_ok=True)

    # If already pointing to the right place, nothing to do.
    if os.path.realpath(default) == os.path.realpath(desired):
        return

    # Remove stale symlink or capture existing contents before replacing.
    if default.is_symlink():
        if os.path.realpath(default) == os.path.realpath(desired):
            return
        default.unlink(missing_ok=True)
    elif default.exists():
        # Move any existing files so we don't lose a generated identity.
        for item in default.iterdir():
            destination = desired / item.name
            if destination.exists():
                continue
            shutil.move(str(item), str(destination))
        shutil.rmtree(default)

    default.symlink_to(desired, target_is_directory=True)
    print(f"Redirected {label} storage to {desired}")


_redirect_rns_storage(_RNS_IDENTITY_DIR, IDENTITY_PATH, "identity")
_redirect_rns_storage(_RNS_LXMF_DIR, LXMF_STORAGE_PATH, "LXMF")

# Propagate the resolved paths to env vars expected by lxmfy/RNS so the
# directories are effectively used when the bot starts.
if IDENTITY_PATH:
    os.environ.setdefault("LXMFBOT_IDENTITY_PATH", IDENTITY_PATH)
    os.environ.setdefault("IDENTITY_PATH", IDENTITY_PATH)

if LXMF_STORAGE_PATH:
    os.environ.setdefault("LXMF_STORAGE_PATH", LXMF_STORAGE_PATH)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def decode_maybe_bytes(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", errors="replace")
    return value


def make_json_safe(value: Any) -> Any:
    """Recursively convert values to JSON-serializable equivalents."""

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()

    if isinstance(value, dict):
        safe_dict = {}
        for key, item in value.items():
            safe_key = make_json_safe(key)
            if not isinstance(safe_key, str):
                safe_key = str(safe_key)
            safe_dict[safe_key] = make_json_safe(item)
        return safe_dict

    if isinstance(value, (list, tuple, set)):
        return [make_json_safe(item) for item in value]

    # Anything else → stringify
    return str(value)


def debug_log(label: str, data: Any | None = None):
    if not DEBUG_WEBHOOK:
        return

    if data is None:
        print(f"[DEBUG] {label}")
        return

    try:
        safe_data = make_json_safe(data)
        print(f"[DEBUG] {label}: {json.dumps(safe_data, ensure_ascii=False)}")
    except Exception:
        print(f"[DEBUG] {label}: {data}")


@dataclass
class WebhookResult:
    data: dict[str, Any] | None
    text: str
    response_time: float


class WebhookCallError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None):
        super().__init__(message)
        self.status = status


def invoke_webhook(payload: dict[str, Any], *, context: str) -> WebhookResult:
    debug_log(f"{context}_payload", payload)

    request_start = time.time()
    try:
        resp = requests.post(
            WEBHOOK_URL,
            json=payload,
            timeout=WEBHOOK_TIMEOUT,
        )
    except Exception as exc:
        debug_log(f"{context}_exception", {"error": str(exc)})
        raise WebhookCallError(f"Webhook call failed: {exc}") from exc

    response_time = time.time() - request_start

    if resp.status_code != 200:
        debug_log(
            f"{context}_http_error",
            {"status": resp.status_code, "text": resp.text},
        )
        raise WebhookCallError(
            f"Webhook error: HTTP {resp.status_code}",
            status=resp.status_code,
        )

    try:
        data = resp.json()
    except ValueError:
        data = None

    return WebhookResult(data=data, text=resp.text.strip(), response_time=response_time)


def record_webhook_success(bot: LXMFBot, elapsed: float):
    bot.messages_processed += 1
    bot.response_times.append(elapsed)
    if len(bot.response_times) > 1000:
        bot.response_times.pop(0)


# ---------------------------------------------------------------------------
# Bot principal
# ---------------------------------------------------------------------------

def create_bot():
    bot = LXMFBot(
        name=BOT_NAME,
        announce=ANNOUNCE_INTERVAL,
        announce_enabled=ANNOUNCE_ENABLED,
        announce_immediately=ANNOUNCE_IMMEDIATELY,
        admins=LXMF_ADMINS,
        hot_reloading=True,
        command_prefix="/",
        rate_limit=5,
        cooldown=5,
        max_warnings=3,
        warning_timeout=300,
        cogs_enabled=False,
        cogs_dir="",
        signature_verification_enabled=SIGNATURE_VERIFICATION_ENABLED,
        require_message_signatures=REQUIRE_MESSAGE_SIGNATURES,
    )

    # Icono del bot
    try:
        icon_data = IconAppearance(
            icon_name=BOT_ICON,
            fg_color=bytes.fromhex(ICON_FG_COLOR),
            bg_color=bytes.fromhex(ICON_BG_COLOR),
        )
        bot.icon_lxmf_field = pack_icon_appearance_field(icon_data)
    except ValueError as e:
        print(f"Warning: Invalid icon color format: {e}. Using default colors.")
        icon_data = IconAppearance(
            icon_name=BOT_ICON,
            fg_color=b"\xff\xff\xff",  # white
            bg_color=b"\x25\x63\xeb",  # blue
        )
        bot.icon_lxmf_field = pack_icon_appearance_field(icon_data)

    # Estadísticas simples
    bot.start_time = time.time()
    bot.messages_processed = 0
    bot.error_count = 0
    bot.response_times = []

    # -----------------------------------------------------------------------
    # Comandos básicos locales (opcional)
    # -----------------------------------------------------------------------

    @bot.command(name="ping", description="Test if bot is responsive")
    def ping_command(ctx):
        ctx.reply("pong", lxmf_fields=bot.icon_lxmf_field)

    @bot.command(name="about", description="Show bot info")
    def about_command(ctx):
        uptime = format_uptime(time.time() - bot.start_time)
        processed = bot.messages_processed
        errors = bot.error_count
        avg_response = None
        if bot.response_times:
            avg_response = sum(bot.response_times) / len(bot.response_times)

        lines = [
            f"{BOT_NAME}",
            "",
            f"Operator: {BOT_OPERATOR}",
            f"Admins: {len(LXMF_ADMINS)} configured",
            f"Uptime: {uptime}",
            f"Messages processed: {processed}",
            f"Errors: {errors}",
            (
                f"Average webhook response: {avg_response:.2f}s"
                if avg_response is not None
                else None
            ),
        ]

        text = "\n".join(filter(None, lines))
        ctx.reply(text, lxmf_fields=bot.icon_lxmf_field)

    # -----------------------------------------------------------------------
    # Manejo de mensajes → webhook n8n
    # -----------------------------------------------------------------------

    @bot.events.on("message_received", EventPriority.NORMAL)
    def handle_message(event):
        """
        Cada mensaje LXMF recibido se envía al webhook de n8n.

        Payload que mandamos (todo JSON-safe):

        {
          "type": "message",
          "sender": "<lxmf_hash_hex>",
          "content": "<texto>",
          "meta": {
            "title": "...",
            "timestamp": ...,
            "hash": "<hash_hex_o_none>",
            "fields": {
              "campo": "<valor_hex>"
            }
          },
          "event": {
            "name": "message_received"
          }
        }
        """
        lxmf_message = event.data.get("message")
        sender_raw = event.data.get("sender")

        if not lxmf_message or not sender_raw:
            return

        # sender puede venir como bytes o string -> lo normalizamos a hex/string
        if isinstance(sender_raw, (bytes, bytearray)):
            sender = RNS.prettyhexrep(sender_raw)
        else:
            sender = str(sender_raw)

        # Intentamos decodificar el contenido
        try:
            content_str = lxmf_message.content.decode(
                "utf-8", errors="replace"
            ).strip()
        except Exception as e:
            bot.send(
                sender_raw,
                f"Error decoding message: {e}",
                lxmf_fields=bot.icon_lxmf_field,
            )
            return

        if not content_str:
            return

        # Si empieza por comando, dejamos que LXMFBot lo maneje
        prefix = getattr(bot, "command_prefix", "/")
        if prefix and content_str.startswith(prefix):
            return

        # --- Meta: asegurar que no haya bytes en hash/fields ---

        msg_hash = getattr(lxmf_message, "hash", None)
        if isinstance(msg_hash, (bytes, bytearray)):
            msg_hash = msg_hash.hex()

        raw_fields = getattr(lxmf_message, "fields", None)
        safe_fields = make_json_safe(raw_fields) if isinstance(raw_fields, dict) else None

        title = decode_maybe_bytes(getattr(lxmf_message, "title", None))
        event_name = decode_maybe_bytes(getattr(event, "name", "message_received"))

        payload = {
            "type": "message",
            "sender": sender,  # siempre string
            "content": content_str,
            "meta": {
                "title": title,
                "timestamp": getattr(lxmf_message, "timestamp", None),
                "hash": msg_hash,
                "fields": safe_fields,
            },
            "event": {
                "name": event_name,
            },
        }

        try:
            result = invoke_webhook(payload, context="webhook_message")
        except WebhookCallError as exc:
            bot.error_count += 1
            bot.send(
                sender_raw,
                str(exc),
                lxmf_fields=bot.icon_lxmf_field,
            )
            return

        record_webhook_success(bot, result.response_time)

        if isinstance(result.data, dict):
            reply_text = (
                result.data.get("reply")
                or result.data.get("response")
                or result.data.get("text")
            )
            title = result.data.get("title") or "Reply"

            if reply_text:
                bot.send(
                    sender_raw,
                    reply_text,
                    title=title,
                    lxmf_fields=bot.icon_lxmf_field,
                )
            return

        if result.text:
            bot.send(
                sender_raw,
                result.text,
                lxmf_fields=bot.icon_lxmf_field,
            )
        # Si no hay reply_text, n8n ha decidido no contestar

    # -----------------------------------------------------------------------
    # Announces → webhook n8n (para saludos, etc., lógica en n8n)
    # -----------------------------------------------------------------------

    # RNS.Transport.register_announce_handler típicamente espera instancias
    # de ``RNS.Transport.AnnounceHandler``. Algunas instalaciones de
    # Reticulum exponen la clase, pero otras no o requieren únicamente que
    # exista el método ``received_announce``. Para maximizar compatibilidad
    # usamos ``getattr`` y, si no existe, heredamos simplemente de ``object``.
    AnnounceHandlerBase = getattr(getattr(RNS, "Transport", object), "AnnounceHandler", object)

    class SimpleAnnounceHandler(AnnounceHandlerBase):
        def __init__(self, bot_instance):
            super().__init__()
            self.bot = bot_instance

        def received_announce(
            self,
            destination_hash,
            announced_identity,
            app_data,
            transport=None,
        ):
            # destination_hash: hash del destino anunciado (bytes)
            dest_hex = RNS.prettyhexrep(destination_hash)

            identity_hash_hex = None
            public_key_hex = None

            if announced_identity is not None:
                try:
                    identity_hash_hex = RNS.prettyhexrep(announced_identity.hash)
                except Exception:
                    identity_hash_hex = None

                try:
                    pk = announced_identity.get_public_key()
                    if pk is not None:
                        public_key_hex = pk.hex()
                except Exception:
                    public_key_hex = None

            app_data_str = (
                app_data.decode("utf-8", errors="replace") if app_data else None
            )

            print(f"[ANN] from={dest_hex}, app_data={app_data_str}")

            payload = {
                "type": "announce",
                "from": dest_hex,
                "identity_hash": identity_hash_hex,
                "public_key": public_key_hex,
                "app_data": app_data_str,
                "event": {
                    "name": "announce",
                },
            }

            try:
                result = invoke_webhook(payload, context="webhook_announce")
            except WebhookCallError as exc:
                print(f"[ANN] {exc}")
                return

            data = result.data if isinstance(result.data, dict) else None
            if not data:
                return

            reply_text = (
                data.get("reply")
                or data.get("response")
                or data.get("text")
            )
            title = data.get("title") or "Hello"

            if reply_text:
                self.bot.send(
                    destination_hash,
                    reply_text,
                    title=title,
                    lxmf_fields=self.bot.icon_lxmf_field,
                )
                print(f"[ANN] reply sent to {dest_hex}")
            else:
                print(f"[ANN] no reply from webhook for {dest_hex}")

    # Registramos el handler de announces en Reticulum
    RNS.Transport.register_announce_handler(SimpleAnnounceHandler(bot))

    return bot


# ---------------------------------------------------------------------------
# Utilidades extra (stats)
# ---------------------------------------------------------------------------

def format_uptime(seconds):
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if seconds or not parts:
        parts.append(f"{seconds}s")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------

def main():
    print(f"Starting {BOT_NAME}...")
    print(f"Webhook URL: {WEBHOOK_URL}")
    if LXMF_ADMINS:
        print(f"Admins: {len(LXMF_ADMINS)} configured")
    print(f"Operator: {BOT_OPERATOR}")
    sig_status = "Enabled" if SIGNATURE_VERIFICATION_ENABLED else "Disabled"
    sig_required = "Yes" if REQUIRE_MESSAGE_SIGNATURES else "No"
    print(f"Signature Verification: {sig_status}")
    print(f"Require Message Signatures: {sig_required}")
    print(f"Bot Icon: {BOT_ICON} (FG={ICON_FG_COLOR}, BG={ICON_BG_COLOR})")
    print(
        "Announce settings: interval={}s, enabled={}, immediate={}".format(
            ANNOUNCE_INTERVAL,
            ANNOUNCE_ENABLED,
            ANNOUNCE_IMMEDIATELY,
        )
    )
    print(f"Webhook debug logging: {'on' if DEBUG_WEBHOOK else 'off'}")
    if IDENTITY_PATH:
        print(f"Identity path: {IDENTITY_PATH}")
    if LXMF_STORAGE_PATH:
        print(f"LXMF storage path: {LXMF_STORAGE_PATH}")

    bot = create_bot()
    bot.run()


if __name__ == "__main__":
    main()
 
