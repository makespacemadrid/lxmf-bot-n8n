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
import os
import time

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

# Paths used to persist identity and LXMF storage. These match the docker-compose
# bind mounts by default but can be overridden via env vars if needed.
DEFAULT_IDENTITY_PATH = "/bot/identity"
DEFAULT_LXMF_STORAGE_PATH = "/bot/lxmf_storage"

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

# Propagate the resolved paths to env vars expected by lxmfy/RNS so the
# directories are effectively used when the bot starts.
if IDENTITY_PATH:
    os.environ.setdefault("LXMFBOT_IDENTITY_PATH", IDENTITY_PATH)
    os.environ.setdefault("IDENTITY_PATH", IDENTITY_PATH)

if LXMF_STORAGE_PATH:
    os.environ.setdefault("LXMF_STORAGE_PATH", LXMF_STORAGE_PATH)


# ---------------------------------------------------------------------------
# Bot principal
# ---------------------------------------------------------------------------

def create_bot():
    bot = LXMFBot(
        name=BOT_NAME,
        announce=600,
        announce_enabled=True,
        announce_immediately=True,
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
        sig_status = "Enabled" if SIGNATURE_VERIFICATION_ENABLED else "Disabled"
        sig_required = "Required" if REQUIRE_MESSAGE_SIGNATURES else "Optional"

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
            f"Signature Verification: {sig_status}",
            f"Message Signatures: {sig_required}",
            f"Bot Icon: {BOT_ICON} (FG={ICON_FG_COLOR}, BG={ICON_BG_COLOR})",
        ]

        if IDENTITY_PATH:
            lines.append(f"Identity path: {IDENTITY_PATH}")
        if LXMF_STORAGE_PATH:
            lines.append(f"LXMF storage: {LXMF_STORAGE_PATH}")

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
        safe_fields = None
        if isinstance(raw_fields, dict):
            safe_fields = {}
            for k, v in raw_fields.items():
                key_str = str(k)
                if isinstance(v, (bytes, bytearray)):
                    safe_fields[key_str] = v.hex()
                else:
                    safe_fields[key_str] = v

        payload = {
            "type": "message",
            "sender": sender,  # siempre string
            "content": content_str,
            "meta": {
                "title": getattr(lxmf_message, "title", None),
                "timestamp": getattr(lxmf_message, "timestamp", None),
                "hash": msg_hash,
                "fields": safe_fields,
            },
            "event": {
                "name": getattr(event, "name", "message_received"),
            },
        }

        request_start = time.time()

        try:
            resp = requests.post(
                WEBHOOK_URL,
                json=payload,
                timeout=WEBHOOK_TIMEOUT,
            )
        except Exception as e:
            bot.error_count += 1
            bot.send(
                sender_raw,
                f"Webhook call failed: {e}",
                lxmf_fields=bot.icon_lxmf_field,
            )
            return

        response_time = time.time() - request_start
        bot.messages_processed += 1
        bot.response_times.append(response_time)
        if len(bot.response_times) > 1000:
            bot.response_times.pop(0)

        if resp.status_code != 200:
            bot.error_count += 1
            bot.send(
                sender_raw,
                f"Webhook error: HTTP {resp.status_code}",
                lxmf_fields=bot.icon_lxmf_field,
            )
            return

        # Intentamos parsear JSON
        try:
            data = resp.json()
        except ValueError:
            # No es JSON: si hay texto plano, lo mandamos tal cual
            text = resp.text.strip()
            if text:
                bot.send(
                    sender_raw,
                    text,
                    lxmf_fields=bot.icon_lxmf_field,
                )
            return

        reply_text = (
            data.get("reply")
            or data.get("response")
            or data.get("text")
        )
        title = data.get("title") or "Reply"

        if reply_text:
            bot.send(
                sender_raw,
                reply_text,
                title=title,
                lxmf_fields=bot.icon_lxmf_field,
            )
        # Si no hay reply_text, n8n ha decidido no contestar

    # -----------------------------------------------------------------------
    # Announces → webhook n8n (para saludos, etc., lógica en n8n)
    # -----------------------------------------------------------------------

    # RNS.Transport.register_announce_handler únicamente necesita un objeto
    # con el método ``received_announce``. Algunas instalaciones de Reticulum
    # no exponen ``RNS.AnnounceHandler`` como clase base pública, por lo que
    # evitamos heredar de ella y usamos un simple contenedor.
    class SimpleAnnounceHandler:
        def __init__(self, bot_instance):
            self.bot = bot_instance

        def received_announce(self, destination_hash, announced_identity, app_data):
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
                resp = requests.post(
                    WEBHOOK_URL,
                    json=payload,
                    timeout=WEBHOOK_TIMEOUT,
                )
            except Exception as e:
                print(f"[ANN] webhook call failed: {e}")
                return

            if resp.status_code != 200:
                print(f"[ANN] webhook HTTP {resp.status_code}")
                return

            # Si el webhook devuelve JSON con "reply", lo enviamos como LXMF
            try:
                data = resp.json()
            except ValueError:
                # No es JSON → ignoramos
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
    if IDENTITY_PATH:
        print(f"Identity path: {IDENTITY_PATH}")
    if LXMF_STORAGE_PATH:
        print(f"LXMF storage path: {LXMF_STORAGE_PATH}")

    bot = create_bot()
    bot.run()


if __name__ == "__main__":
    main()
 
