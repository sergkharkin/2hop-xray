#!/bin/bash
# push-lists.sh — раскатка списков доменов на все роутеры через панель :8888.
#
# Панель остаётся единственным местом, которое правит конфиги: скрипт лишь
# дёргает её HTTP-эндпоинт (action=rules&format=text), поэтому бэкап,
# `xray -test` и откат при ошибке отрабатывают на каждом роутере штатно.
#
# Использование:
#   ./push-lists.sh                      # merge: добавить домены из lists/*.txt
#   ./push-lists.sh --replace            # заменить списки лейнов целиком
#                                        (файл должен содержать ПОЛНЫЙ список —
#                                         панель отклонит частичный)
#   ./push-lists.sh --only glinet,narr   # только указанные роутеры
#   ./push-lists.sh --config-only        # не трогать шаблоны, только config.json
#   ./push-lists.sh --dry-run            # показать, что было бы отправлено
#
# Файлы (рядом со скриптом, оба в .gitignore):
#   routers.conf   — строки «имя  хост[:порт]  [логин:пароль]»
#   lists/foreign.txt — заграничные ресурсы (правило hop-list-foreign)
#   lists/ru.txt      — российские ресурсы  (правило hop-list-ru)
#                       домен на строку, # — комментарий
#
# Куда ведёт лейн, решает каждый конфиг сам (outboundTag его правила-списка):
# в прямом режиме foreign→proxy, ru→direct/entry-hop; в обратном (роутер за
# границей, выход в РФ) foreign→direct, ru→proxy. Поэтому один и тот же набор
# списков безопасно раскатывать на весь флот, включая «обратные» роутеры.

set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROUTERS_FILE="${HOP_ROUTERS:-$DIR/routers.conf}"
LISTS_DIR="${HOP_LISTS:-$DIR/lists}"
DEFAULT_AUTH="${HOP_AUTH:-admin:xray-hop}"

MODE=merge
ONLY=""
DRY=0
T_CONFIG=1
T_TEMPLATES=1

while [ $# -gt 0 ]; do
    case "$1" in
        --replace)      MODE=replace ;;
        --merge)        MODE=merge ;;
        --only)         ONLY="${2:?--only требует список имён через запятую}"; shift ;;
        --only=*)       ONLY="${1#*=}" ;;
        --config-only)  T_TEMPLATES=0 ;;
        --templates-only) T_CONFIG=0 ;;
        --dry-run)      DRY=1 ;;
        -h|--help)      sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "Неизвестный аргумент: $1" >&2; exit 2 ;;
    esac
    shift
done

[ -f "$ROUTERS_FILE" ] || { echo "Нет файла роутеров: $ROUTERS_FILE" >&2; exit 1; }
# новые имена, со старыми как fallback
RU="$LISTS_DIR/ru.txt";           [ -f "$RU" ]      || RU="$LISTS_DIR/direct.txt"
FOREIGN="$LISTS_DIR/foreign.txt"; [ -f "$FOREIGN" ] || FOREIGN="$LISTS_DIR/proxy.txt"
[ -f "$RU" ]      || { echo "Нет $LISTS_DIR/ru.txt" >&2; exit 1; }
[ -f "$FOREIGN" ] || { echo "Нет $LISTS_DIR/foreign.txt" >&2; exit 1; }

n_ru=$(grep -cve '^\s*$' -e '^\s*#' "$RU" || true)
n_foreign=$(grep -cve '^\s*$' -e '^\s*#' "$FOREIGN" || true)

echo "режим: $MODE · заграничных: $n_foreign · российских: $n_ru"
echo "цели: $( [ $T_CONFIG = 1 ] && printf 'config.json ' )$( [ $T_TEMPLATES = 1 ] && printf 'шаблоны' )"
echo "────────────────────────────────────────────────────────"

ok=0; failed=0; skipped=0

while read -r name host auth _rest; do
    case "${name:-}" in ''|\#*) continue ;; esac
    auth="${auth:-$DEFAULT_AUTH}"

    if [ -n "$ONLY" ] && ! printf '%s' ",$ONLY," | grep -q ",$name,"; then
        continue
    fi

    printf '%-10s %-20s ' "$name" "$host"

    if [ "$DRY" = 1 ]; then
        echo "[dry-run] POST http://$host/cgi-bin/update-hop action=rules mode=$MODE"
        continue
    fi

    args=(--data "action=rules" --data "format=text" --data "mode=$MODE")
    [ $T_CONFIG    = 1 ] && args+=(--data "t_config=1")
    [ $T_TEMPLATES = 1 ] && args+=(--data "t_templates=1")
    args+=(--data-urlencode "list_ru@$RU")
    args+=(--data-urlencode "list_foreign@$FOREIGN")

    resp=$(curl -sS --max-time 300 --connect-timeout 8 -u "$auth" \
           "${args[@]}" "http://$host/cgi-bin/update-hop" 2>&1)
    rc=$?

    if [ $rc -ne 0 ]; then
        echo "НЕДОСТУПЕН (curl $rc)"
        echo "           $resp" | head -2
        skipped=$((skipped + 1))
    elif printf '%s' "$resp" | grep -q '^OK '; then
        echo "$(printf '%s' "$resp" | head -1)"
        printf '%s\n' "$resp" | tail -n +2 | sed 's/^/           /'
        ok=$((ok + 1))
    else
        echo "ОШИБКА"
        printf '%s\n' "$resp" | head -5 | sed 's/^/           /'
        failed=$((failed + 1))
    fi
done < "$ROUTERS_FILE"

echo "────────────────────────────────────────────────────────"
echo "успешно: $ok · с ошибкой: $failed · недоступно: $skipped"
[ $failed -eq 0 ] || exit 1
