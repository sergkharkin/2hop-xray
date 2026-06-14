#!/bin/sh
# /etc/xray/proxy-toggle.sh
# Включает/выключает Xray-клиент и прозрачный прокси на роутере.
# Состояние сохраняется через файл-флаг /etc/xray/disabled, который
# проверяется в /etc/rc.local при загрузке.
#
# usage: proxy-toggle.sh {on|off|status}

FLAG=/etc/xray/disabled

teardown_redirect() {
    iptables -t nat -D PREROUTING -i br-lan -p tcp -j XRAY 2>/dev/null
    iptables -t nat -F XRAY 2>/dev/null
    iptables -t nat -X XRAY 2>/dev/null
    iptables -D FORWARD -i br-lan -p udp --dport 443 -j REJECT 2>/dev/null
}

case "$1" in
    off)
        /etc/init.d/xray stop 2>/dev/null
        /etc/init.d/xray disable
        uci set xray.enabled.enabled='0'
        uci commit xray
        teardown_redirect
        touch "$FLAG"
        echo "OFF: xray остановлен, автозапуск выключен, NAT-правила удалены."
        echo "Роутер работает как обычный шлюз без кастомной маршрутизации."
        ;;
    on)
        rm -f "$FLAG"
        uci set xray.enabled.enabled='1'
        uci commit xray
        /etc/init.d/xray enable
        /etc/init.d/xray start
        sleep 1
        /etc/xray/transparent-proxy.sh
        echo "ON: xray запущен, автозапуск включён, прозрачный прокси активирован."
        ;;
    status)
        if [ -f "$FLAG" ]; then
            echo "flag         : OFF (присутствует $FLAG)"
        else
            echo "flag         : ON  (отсутствует $FLAG)"
        fi
        /etc/init.d/xray enabled \
            && echo "autostart    : enabled" \
            || echo "autostart    : disabled"
        XPID=$(pidof xray)
        if [ -n "$XPID" ]; then
            echo "xray process : running (pid $XPID)"
        else
            echo "xray process : stopped"
        fi
        if iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q 'XRAY'; then
            echo "redirect rule: present"
        else
            echo "redirect rule: absent"
        fi
        ;;
    *)
        echo "usage: $0 {on|off|status}"
        exit 1
        ;;
esac
