# Xray Hop Updater — инструкция по установке

Веб-интерфейс на порту 8888 для управления двухшаговым Xray VLESS-прокси на роутере OpenWRT/GL.iNet.

## Что умеет

- Применять шаблон конфига (exit hop) + новый entry-hop из `vless://` строки, JSON-текста или JSON-файла
- Применять `.json.bak` файл как есть — без изменений
- Восстанавливать из автоматических бэкапов
- Валидировать конфиг через `xray -test` перед применением
- Сохранять бэкап текущего `config.json` перед каждой заменой
- Обновлять geo-файлы (`geoip.dat`, `geosite.dat`, `geosite-v2fly.dat`) кнопками — с бэкапом, проверкой и откатом
- Включать/выключать Xray-клиент (если на роутере есть `proxy-toggle.sh`)

---

## Требования на роутере

| Компонент | Версия | Проверка |
|---|---|---|
| OpenWRT | 21+ | `cat /etc/openwrt_release` |
| uhttpd | любая | `uhttpd -v` |
| lua | 5.1+ | `lua -v` |
| lua-cjson | любая | `lua -e 'require("cjson")'` |
| xray | любая | `/usr/bin/xray version` |

Если `lua-cjson` не установлен:
```
opkg update && opkg install lua-cjson
```

Xray должен быть установлен в `/usr/bin/xray` и иметь init-скрипт `/etc/init.d/xray`.  
Dat-файлы должны быть доступны xray на роутере — см. раздел «Geo-файлы» ниже.

---

## Geo-файлы (geoip.dat / geosite.dat / geosite-v2fly.dat)

### Где должны лежать

Все `.dat`-файлы лежат в **asset-каталоге xray**. По умолчанию это
`/usr/share/xray/`:

```
/usr/share/xray/geoip.dat
/usr/share/xray/geosite.dat
/usr/share/xray/geosite-v2fly.dat
```

Каталог задаётся переменной окружения `XRAY_LOCATION_ASSET`, которую init-скрипт
GL.iNet берёт из UCI-опции `xray.config.datadir` (дефолт `/usr/share/xray`):

```bash
# init.d/xray:  procd_set_param env XRAY_LOCATION_ASSET="$datadir"
uci get xray.config.datadir        # → /usr/share/xray
```

Проверить наличие файлов и текущий asset-каталог:

```bash
ls -la /usr/share/xray/*.dat
PID=$(pgrep -f /usr/bin/xray); tr '\0' '\n' < /proc/$PID/environ | grep XRAY_LOCATION_ASSET
```

> `geosite-v2fly.dat` обязан лежать именно в asset-каталоге рядом с `geoip.dat`
> и `geosite.dat` — иначе xray не найдёт его и `xray -test` упадёт на правилах
> `ext:geosite-v2fly.dat:…`.

### Откуда берётся какой файл

Имя файла определяется **префиксом** в правиле маршрутизации:

| Префикс в правиле | Где встречается | Из какого файла грузится |
|---|---|---|
| `geoip:ru`, `geoip:by`, `geoip:PRIVATE` | правила `ip` (поле `"ip"`) | `geoip.dat` (имя по умолчанию для `geoip:`) |
| `geosite:<категория>` | правила `domain` (поле `"domain"`) | `geosite.dat` (имя по умолчанию для `geosite:`) |
| `ext:geosite-v2fly.dat:<категория>` | правила `domain` | `geosite-v2fly.dat` (имя задано явно через `ext:`) |

То есть:

- **IP-правила** (`"ip": ["geoip:ru", "geoip:by", "geoip:PRIVATE"]`) тянут данные из
  **`geoip.dat`** — префикс `geoip:` всегда указывает на файл с этим именем в asset-каталоге.
- **Domain-правила** тянут данные из **`geosite.dat`** (если префикс `geosite:`) или
  из **`geosite-v2fly.dat`** (если префикс `ext:geosite-v2fly.dat:`). Конструкция
  `ext:<имя-файла>.dat:<категория>` позволяет грузить категории из любого
  альтернативного файла в том же каталоге — здесь используется набор от проекта
  v2fly.

### Обновление файлов

#### Через панель (кнопки «Обновить»)

В веб-интерфейсе есть карточка **«Geo-файлы»** с тремя кнопками — по одной на
каждый файл. Рядом показывается текущий размер файла и источник. По нажатию
панель выполняет на роутере:

1. `curl -fL` скачивает файл во временный `.<имя>.new` в asset-каталоге
   (тот же fs → атомарная подмена; таймаут curl 180 с);
2. проверяет размер (защита от HTML-страницы ошибки / обрыва);
3. переименовывает текущий файл в `<имя>.bak`, ставит новый на его место;
4. `xray -test` на текущем `config.json` с `XRAY_LOCATION_ASSET=<asset-каталог>`;
5. если OK — **перезапускает xray**; если файл не прошёл проверку — **откатывает**
   из `.bak` и xray не трогает.

Источники (зашиты в `update-hop.lua`, таблица `GEO`):

| Файл | URL |
|---|---|
| `geoip.dat` | `github.com/Loyalsoldier/v2ray-rules-dat` → `releases/latest/download/geoip.dat` |
| `geosite.dat` | `github.com/Loyalsoldier/v2ray-rules-dat` → `releases/latest/download/geosite.dat` |
| `geosite-v2fly.dat` | `github.com/v2fly/domain-list-community` → `releases/latest/download/dlc.dat` |

> Для скачивания на роутере нужны `curl` + `ca-certificates`/`ca-bundle` +
> `libustream-*ssl` (на GL.iNet обычно уже есть). uhttpd-инстанс панели держит
> `script_timeout`/`network_timeout` = 300 с, чтобы крупный `geoip.dat` (~19 МБ)
> успел скачаться.

Поменять источник — отредактируй таблицу `GEO` в `update-hop.lua` и передеплой.

#### Вручную (scp)

`.dat` можно заменить и руками — файл должен называться ровно так, как в правилах,
и лежать в asset-каталоге; после замены нужен рестарт xray:

```bash
scp geosite-v2fly.dat glinet:/usr/share/xray/geosite-v2fly.dat
ssh glinet "/etc/init.d/xray restart"
```

---

## Включение / выключение Xray-клиента (toggle)

Если на роутере есть скрипт **`/etc/xray/proxy-toggle.sh`**, в панели появляется
карточка **«Xray-клиент (прокси)»** с кнопками **Включить** / **Выключить** и
текущим состоянием. Если скрипта нет — карточка не показывается (на таких
роутерах xray всегда в автозапуске).

Кнопки вызывают `proxy-toggle.sh {on|off}`:

- **off** — `xray stop`, отключение автозапуска (`uci xray.enabled.enabled='0'` +
  `/etc/init.d/xray disable`), снос NAT-правил прозрачного прокси, установка флага
  `/etc/xray/disabled`. Роутер работает обычным шлюзом.
- **on** — снятие флага, включение автозапуска, `xray start`, повторный прогон
  `transparent-proxy.sh`.

Флаг `/etc/xray/disabled` **переживает перезагрузку**: в `/etc/rc.local` стоит
проверка `[ -f /etc/xray/disabled ] || /etc/xray/transparent-proxy.sh`, поэтому
выключенный прокси не поднимется сам после ребута.

> Связь с обновлением geo-файлов: панель перезапускает xray после обновления
> `.dat` **только если он был запущен**. На выключенном через toggle роутере файл
> обновится, но xray не поднимется — новый `.dat` применится при следующем
> `proxy-toggle.sh on`.

### Установка toggle на новый роутер

`deploy.sh` скрипт **не** ставит — он специфичен для схемы прозрачного прокси
конкретного роутера (интерфейс `br-lan`, redir-порт xray). Чтобы добавить:

```bash
# 1. Скопировать скрипт (можно взять с роутера, где он уже есть)
scp proxy-toggle.sh <router>:/etc/xray/proxy-toggle.sh
ssh <router> "chmod +x /etc/xray/proxy-toggle.sh"

# 2. Научить rc.local уважать флаг отключения
ssh <router> "sed -i 's#^/etc/xray/transparent-proxy.sh\$#[ -f /etc/xray/disabled ] || /etc/xray/transparent-proxy.sh#' /etc/rc.local"
```

После этого карточка появится в панели автоматически (CGI проверяет наличие
скрипта при каждом запросе).

---

## Состав папки

```
hop-deploy/
├── DEPLOY.md          — эта инструкция
├── deploy.sh          — скрипт автоматической установки
├── update-hop.lua     — CGI скрипт (главный файл)
├── proxy-toggle.sh    — вкл/выкл Xray-клиента (ставится вручную, см. раздел toggle)
└── hop-ui/
    └── index.html     — редирект с http://router:8888/ на страницу
```

Шаблоны конфигов (`config-*.json.bak`) хранятся отдельно — они специфичны для каждой связки серверов.

---

## Быстрая установка (deploy.sh)

```bash
# Базовая установка (пароль по умолчанию: admin:xray-hop)
./deploy.sh glinet

# С кастомным паролем
./deploy.sh glinet admin:mysecretpassword

# На роутер по IP
./deploy.sh root@192.168.8.1 admin:mysecretpassword
```

Скрипт выполняет 6 шагов автоматически:
1. Проверка SSH-подключения
2. Установка `lua-cjson` (если не установлен, запускает `opkg install`)
3. Копирование CGI скрипта
4. Настройка docroot `/www/hop-ui`
5. Создание файла авторизации
6. Настройка uhttpd на порту 8888

Копирование файлов работает на роутерах как с `sftp-server`, так и без него (fallback через SSH pipe).

После завершения скопируй шаблоны конфигов:

```bash
scp config-*.json.bak glinet:/etc/xray/
```

---

## Ручная установка (шаг за шагом)

### 1. CGI скрипт

```bash
scp update-hop.lua root@<router>:/www/cgi-bin/update-hop
ssh root@<router> "chmod +x /www/cgi-bin/update-hop"
```

### 2. Docroot для порта 8888

```bash
ssh root@<router> "mkdir -p /www/hop-ui/cgi-bin"
scp hop-ui/index.html root@<router>:/www/hop-ui/index.html
ssh root@<router> "ln -sf /www/cgi-bin/update-hop /www/hop-ui/cgi-bin/update-hop"
```

### 3. Файл авторизации

```bash
echo -n "admin:yourpassword" | ssh root@<router> "cat > /etc/xray/hop-auth && chmod 600 /etc/xray/hop-auth"
```

Формат файла: `логин:пароль` — одна строка, без переноса, без пробелов.

### 4. Настройка uhttpd

На роутере выполни:

```bash
# Убираем порт 8888 из основного инстанса (если был добавлен ранее)
uci del_list uhttpd.main.listen_http='0.0.0.0:8888' 2>/dev/null || true

# Создаём отдельный инстанс для порта 8888
uci set uhttpd.hop=uhttpd
uci set uhttpd.hop.home='/www/hop-ui'
uci set uhttpd.hop.cgi_prefix='/cgi-bin'
uci set uhttpd.hop.script_timeout=60
uci set uhttpd.hop.network_timeout=30
uci set uhttpd.hop.tcp_keepalive=1
uci add_list uhttpd.hop.listen_http='0.0.0.0:8888'
uci commit uhttpd
/etc/init.d/uhttpd restart
```

Проверка — должно быть два процесса uhttpd:
```bash
ps | grep uhttpd | grep -v grep
# /usr/sbin/uhttpd -f -h /www ...           ← основной (LuCI)
# /usr/sbin/uhttpd -f -h /www/hop-ui ...    ← наш
```

### 5. Шаблоны конфигов

```bash
scp config-*.json.bak root@<router>:/etc/xray/
```

---

## Шаблоны конфигов (config-*.json.bak)

Шаблон — это готовый xray-конфиг для двух хопов. Веб-интерфейс использует его так:

- **Форма «Шаблон + entry-hop»** — берёт шаблон, подставляет новый entry-hop, добавляет `dialerProxy`, валидирует, применяет. Креды entry-hop можно задать тремя способами (см. ниже).
- **Форма «Прямая замена»** — применяет файл как есть.

### Три способа задать entry-hop в форме «Шаблон + entry-hop»

В одной форме доступны три варианта ввода кредов entry-hop. Если заполнено
несколько — действует приоритет: **файл → JSON-текст → `vless://`**.

1. **Строка `vless://…`** — стандартная VLESS-ссылка.
2. **Вставка JSON-текста** — вставь в поле содержимое клиентского xray-конфига
   (как `example.txt`). Панель найдёт в нём vless-outbound и возьмёт креды.
3. **Загрузка JSON-файла** — выбери `.json`/`.txt` файл клиентского xray-конфига.

Для способов 2 и 3 панель ищет в `outbounds` узел с `protocol: "vless"` и тегом
`proxy` (или `exit-hop`); если таких нет — берёт первый vless-outbound.
Поддерживается и файл, состоящий из одного outbound-объекта. Извлекаются:
`address`/`port`, `users[0].id`, `flow`, `network`, `security` и
`realitySettings` (`serverName`, `fingerprint`, `publicKey`, `shortId`) — те же
поля, что и из `vless://`-строки.

### Структура шаблона

Минимальный рабочий шаблон для 2-хоп цепочки:

```json
{
  "log": { "loglevel": "warning", ... },
  "inbounds": [ ... ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": {
        "vnext": [{ "address": "<EXIT-HOP-IP>", "port": 443,
          "users": [{ "id": "<UUID>", "encryption": "none", "flow": "xtls-rprx-vision" }]
        }]
      },
      "streamSettings": {
        "network": "tcp", "security": "reality",
        "realitySettings": {
          "serverName": "<SNI>", "fingerprint": "chrome",
          "publicKey": "<PUBKEY>", "shortId": "<SID>"
        },
        "sockopt": { "dialerProxy": "entry-hop" }
      }
    },
    {
      "tag": "entry-hop",
      "protocol": "vless",
      "settings": { ... },
      "streamSettings": { ... }
    },
    { "tag": "direct", "protocol": "freedom", "settings": {} },
    { "tag": "block", "protocol": "blackhole", "settings": {} }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": ["<EXIT-HOP-IP>/32", "<ENTRY-HOP-IP>/32"],
        "outboundTag": "direct"
      },
      ...
    ]
  }
}
```

**Важно:**
- В `routing` обязательно добавь IP обоих серверов (exit и entry hop) в правило `direct` — иначе трафик зациклится через прокси.
- `dialerProxy: "entry-hop"` в `sockopt` у `proxy` outbound — именно так работает цепочка хопов.
- Если используешь форму «Шаблон + entry-hop», `dialerProxy` и `entry-hop` outbound подставляются автоматически — в шаблоне уже должна быть правильная заглушка entry-hop, которая будет заменена.

### Именование файлов

Шаблон называется `config-NAME.json.bak`, где `NAME` — произвольное имя.  
Примеры: `config-RU1-ML1.json.bak`, `config-DE1-AT1.json.bak`.

В dropdown веб-интерфейса рядом с именем показывается IP exit hop.

---

## Смена пароля

На роутере:
```bash
echo -n "admin:newpassword" > /etc/xray/hop-auth
chmod 600 /etc/xray/hop-auth
```

Перезапускать ничего не нужно — пароль читается при каждом запросе.

---

## Файрвол

Порт 8888 доступен только из локальной сети (LAN).  
Снаружи (WAN) он закрыт стандартными правилами OpenWRT — без дополнительных настроек.

---

## Бэкапы

Перед каждой заменой `config.json` автоматически создаётся бэкап:
```
/etc/xray/config.json.20260608_142030
```

Восстановить из бэкапа можно прямо в веб-интерфейсе (секция «Восстановить из бэкапа»).

Старые бэкапы можно удалить вручную:
```bash
ls /etc/xray/config.json.2*
rm /etc/xray/config.json.20260101_*
```
