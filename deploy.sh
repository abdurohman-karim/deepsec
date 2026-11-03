#!/usr/bin/env bash
# Выкладка бота на сервер. Запускать с вашего компьютера из папки проекта:
#   ./deploy.sh root@IP_СЕРВЕРА          — выложить / обновить
#   ./deploy.sh root@IP_СЕРВЕРА login    — подключить сторожа аккаунта (QR-код с телефона)
# Пароль (или ключ) SSH вводите вы сами. Повторный запуск = обновление.
# На Windows — из Git Bash (не из PowerShell): там нет rsync, поэтому файлы едут через tar.
set -euo pipefail

if [ -z "${1:-}" ]; then
    echo "Использование: ./deploy.sh user@host [login]   (например: ./deploy.sh root@203.0.113.10)" >&2
    exit 1
fi
HOST=$1
DIR=/home/bots/deepsec
SERVICE=deepsec-bot
SSH_OPTS="-o ControlMaster=auto -o ControlPath=/tmp/deepsec-deploy-%r@%h:%p -o ControlPersist=120"
case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*) SSH_OPTS="" ;;  # в Git Bash общее SSH-соединение не работает — пароль спросят пару раз
esac

cd "$(dirname "$0")"
run() { ssh $SSH_OPTS "$HOST" "$@"; }

run "mkdir -p $DIR"
# На сервер едет только нужное для работы; .env, data/ и .venv/ на сервере не трогаются
FILES=(deepsec requirements.txt .env.example "$SERVICE.service")
if command -v rsync >/dev/null; then
    rsync -az --delete -e "ssh $SSH_OPTS" --exclude '__pycache__' "${FILES[@]}" "$HOST:$DIR/"
else
    # Без rsync: старый код удаляем целиком, как сделал бы --delete
    tar -czf - --exclude '__pycache__' "${FILES[@]}" | run "cd $DIR && rm -rf deepsec && tar -xzf -"
fi

run "DIR=$DIR SERVICE=$SERVICE SERVER_HOST=${HOST#*@} bash -s" <<'REMOTE'
set -euo pipefail
cd "$DIR"

if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
    echo ">>> Нужен Python 3.10+, на сервере $(python3 --version 2>&1)"
    exit 1
fi

if [ ! -x .venv/bin/pip ]; then
    if ! python3 -m venv .venv 2>/dev/null; then
        apt-get update -qq && apt-get install -y -qq python3-venv
        python3 -m venv .venv
    fi
fi

# Зависимости ставятся только когда requirements.txt изменился
REQ_HASH=$(sha256sum requirements.txt | cut -d' ' -f1)
if [ "$(cat .venv/.requirements.sha256 2>/dev/null)" != "$REQ_HASH" ]; then
    .venv/bin/pip install -q --upgrade pip
    .venv/bin/pip install -q -r requirements.txt
    echo "$REQ_HASH" > .venv/.requirements.sha256
fi

if [ ! -f .env ]; then
    cp .env.example .env
    chmod 600 .env
fi
set_env() {
    if grep -q "^$1=" .env; then sed -i "s|^$1=.*|$1=$2|" .env; else echo "$1=$2" >> .env; fi
}

# Секреты создаются сами при первой выкладке
NEW_TOKEN=""
if ! grep -q '^AGENT_TOKEN=.' .env; then
    NEW_TOKEN=$(.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(32))')
    set_env AGENT_TOKEN "$NEW_TOKEN"
fi
if ! grep -q '^TOTP_SECRET=.' .env; then
    TOTP=$(.venv/bin/python -c 'import pyotp; print(pyotp.random_base32())')
    set_env TOTP_SECRET "$TOTP"
    echo
    echo ">>> 🔑 Добавьте в приложение-аутентификатор НА ТЕЛЕФОНЕ (Aegis, Google Authenticator, 2FAS):"
    echo ">>>    секрет $TOTP"
    echo ">>>    Без него не выключить защиту из бота. Сохраните его офлайн — больше он показан не будет."
fi

# Свой TLS-сертификат для агентов: агент проверяет его отпечаток, поэтому домен не нужен
mkdir -p data/tls
chmod 700 data
if [ ! -f data/tls/cert.pem ]; then
    command -v openssl >/dev/null || { apt-get update -qq && apt-get install -y -qq openssl; }
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 -subj "/CN=deepsec" \
        -keyout data/tls/key.pem -out data/tls/cert.pem 2>/dev/null
    chmod 600 data/tls/key.pem
fi
PORT=$(sed -n 's/^LISTEN_PORT=//p' .env)
PORT=${PORT:-8443}
FINGERPRINT=$(openssl x509 -in data/tls/cert.pem -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr 'A-F' 'a-f')

echo
echo ">>> Для установки агента на Windows (python -m deepsec setup):"
echo ">>>    адрес сервера: $SERVER_HOST, порт: $PORT"
echo ">>>    отпечаток:     $FINGERPRINT"
if [ -n "$NEW_TOKEN" ]; then
    echo ">>>    AGENT_TOKEN:   $NEW_TOKEN"
else
    echo ">>>    AGENT_TOKEN:   grep AGENT_TOKEN $DIR/.env"
fi
# Порт может быть занят другой программой (например, Apache) — тогда агенты не подключатся
if ss -ltnp "sport = :$PORT" | grep -q LISTEN && ! ss -ltnp "sport = :$PORT" | grep -q python; then
    echo ">>> ⚠️  Порт $PORT занят: $(ss -ltnp "sport = :$PORT" | grep -o 'users:(("[^"]*' | cut -d'"' -f2 | head -1)."
    echo ">>>     Впишите свободный порт в LISTEN_PORT (nano $DIR/.env) и запустите ./deploy.sh ещё раз."
fi
# Брандмауэр с политикой DROP без правила для порта — агенты не достучатся (порт сам не открываем:
# это настройка безопасности сервера, решает владелец)
if command -v ufw >/dev/null && ufw status | grep -q "Status: active" && ! ufw status | grep -q "^$PORT/tcp"; then
    echo ">>> ⚠️  Брандмауэр ufw включён — откройте порт агентам: ufw allow $PORT/tcp"
elif iptables -S INPUT 2>/dev/null | grep -q -- "-P INPUT DROP" \
        && ! iptables -S INPUT | grep -E -- "--dports? " | grep -qw -- "$PORT"; then
    if [ -x /usr/local/hestia/bin/v-add-firewall-rule ]; then
        echo ">>> ⚠️  Брандмауэр HestiaCP не пускает агентов на порт $PORT. Откройте его:"
        echo ">>>     /usr/local/hestia/bin/v-add-firewall-rule ACCEPT 0.0.0.0/0 $PORT TCP DeepSec"
    else
        echo ">>> ⚠️  Брандмауэр (iptables, политика DROP) не пускает агентов на порт $PORT — добавьте правило для него."
    fi
fi

if ! grep -q '^BOT_TOKEN=.' .env || ! grep -q '^OWNER_ID=.' .env; then
    echo
    echo ">>> Впишите BOT_TOKEN и OWNER_ID (и для сторожа TG_API_ID, TG_API_HASH) в $DIR/.env:"
    echo ">>>   nano $DIR/.env"
    echo ">>> затем запустите ./deploy.sh ещё раз."
    exit 0
fi

cp "$SERVICE.service" "/etc/systemd/system/$SERVICE.service"
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1
systemctl restart "$SERVICE"
sleep 3
systemctl --no-pager --lines=15 status "$SERVICE" || true

if grep -q '^TG_API_ID=.' .env && [ ! -f data/guard.session ]; then
    echo
    echo ">>> Сторож ещё не вошёл в аккаунт: ./deploy.sh <этот хост> login"
fi
REMOTE

if [ "${2:-}" = "login" ]; then
    # Вход — уже на свежем коде. Сторож держит файл сеанса открытым, поэтому бот на время входа остановлен
    ssh -t $SSH_OPTS "$HOST" \
        "systemctl stop $SERVICE; cd $DIR && .venv/bin/python -m deepsec.server login; systemctl start $SERVICE"
fi
