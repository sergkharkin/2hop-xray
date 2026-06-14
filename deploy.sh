#!/bin/bash
# deploy.sh — установка Xray Hop Updater на OpenWRT/GL.iNet роутер
#
# Использование:
#   ./deploy.sh <ssh-роутер>                    # пароль по умолчанию admin:xray-hop
#   ./deploy.sh <ssh-роутер> <логин:пароль>     # свой пароль
#
# Примеры:
#   ./deploy.sh glinet
#   ./deploy.sh root@192.168.8.1 admin:mypassword

set -e

ROUTER="${1:?Укажи SSH-алиас или user@host роутера (например: glinet или root@192.168.8.1)}"
AUTH="${2:-admin:xray-hop}"
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==> Деплой Xray Hop Updater на $ROUTER"
echo ""

# Копирование файла: scp если есть sftp-server, иначе SSH pipe
copy_file() {
    local src="$1"
    local dst="$2"
    if scp "$src" "$ROUTER:$dst" 2>/dev/null; then
        return 0
    fi
    # Fallback: SSH stdin pipe (работает без sftp-server)
    ssh "$ROUTER" "cat > $dst" < "$src"
}

# ── Проверка доступности роутера ─────────────────────────────────────────────
echo "[1/6] Проверка SSH-подключения..."
ssh -o ConnectTimeout=5 "$ROUTER" "echo ok" > /dev/null
echo "      ✓ Соединение установлено"

# ── Зависимости ──────────────────────────────────────────────────────────────
echo "[2/6] Проверка зависимостей (lua, lua-cjson)..."
if ! ssh "$ROUTER" "which lua" 2>/dev/null 1>/dev/null; then
    echo "      lua не найден, устанавливаем..."
    ssh "$ROUTER" "opkg update && opkg install lua"
fi
if ! ssh "$ROUTER" "lua -e 'require(\"cjson\")'" 2>/dev/null; then
    echo "      lua-cjson не найден, устанавливаем..."
    ssh "$ROUTER" "opkg update 2>/dev/null; opkg install lua-cjson"
fi
echo "      ✓ lua + lua-cjson"

# ── CGI скрипт ───────────────────────────────────────────────────────────────
echo "[3/6] Копируем CGI скрипт..."
copy_file "$DIR/update-hop.lua" "/www/cgi-bin/update-hop"
ssh "$ROUTER" "chmod +x /www/cgi-bin/update-hop"
echo "      ✓ /www/cgi-bin/update-hop"

# ── Docroot для порта 8888 ────────────────────────────────────────────────────
echo "[4/6] Настраиваем docroot /www/hop-ui..."
ssh "$ROUTER" "mkdir -p /www/hop-ui/cgi-bin"
copy_file "$DIR/hop-ui/index.html" "/www/hop-ui/index.html"
ssh "$ROUTER" "ln -sf /www/cgi-bin/update-hop /www/hop-ui/cgi-bin/update-hop"
echo "      ✓ /www/hop-ui/index.html + symlink на CGI"

# ── Файл авторизации ─────────────────────────────────────────────────────────
echo "[5/6] Создаём файл авторизации ($AUTH)..."
printf '%s' "$AUTH" | ssh "$ROUTER" "cat > /etc/xray/hop-auth && chmod 600 /etc/xray/hop-auth"
echo "      ✓ /etc/xray/hop-auth"

# ── uhttpd — отдельный инстанс на порту 8888 ─────────────────────────────────
echo "[6/6] Настраиваем uhttpd на порту 8888..."
ssh "$ROUTER" "
  uci del_list uhttpd.main.listen_http='0.0.0.0:8888' 2>/dev/null || true
  uci -q delete uhttpd.hop || true
  uci set uhttpd.hop=uhttpd
  uci set uhttpd.hop.home='/www/hop-ui'
  uci set uhttpd.hop.cgi_prefix='/cgi-bin'
  uci set uhttpd.hop.script_timeout=300
  uci set uhttpd.hop.network_timeout=300
  uci set uhttpd.hop.tcp_keepalive=1
  uci add_list uhttpd.hop.listen_http='0.0.0.0:8888'
  uci commit uhttpd
  /etc/init.d/uhttpd restart
"
echo "      ✓ uhttpd.hop настроен и запущен"

# ── Шаблоны конфигов (если есть рядом с deploy.sh) ───────────────────────────
echo ""
BAK_FILES=("$DIR"/config-*.json.bak)
if [ -e "${BAK_FILES[0]}" ]; then
    echo "[+] Копируем шаблоны конфигов..."
    for f in "$DIR"/config-*.json.bak; do
        copy_file "$f" "/etc/xray/$(basename "$f")"
    done
    echo "    ✓ Скопированы: $(ls "$DIR"/config-*.json.bak | xargs -n1 basename | tr '\n' ' ')"
else
    echo "[!] Шаблоны config-*.json.bak не найдены рядом с deploy.sh"
    echo "    Скопируй вручную: scp config-*.json.bak $ROUTER:/etc/xray/"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Готово!"
echo "  Веб-интерфейс : http://<IP-роутера>:8888"
echo "  Логин:пароль  : $AUTH"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Следующий шаг: создай шаблоны конфигов в /etc/xray/"
echo "Подробности: см. DEPLOY.md"
