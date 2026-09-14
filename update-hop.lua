#!/usr/bin/env lua
-- Xray Hop Updater — Lua CGI для OpenWRT/GL.iNet
-- Размещать: /www/cgi-bin/update-hop  (chmod +x)

local cjson = require('cjson')
cjson.encode_sparse_array(true)

local CONFIG_DIR  = '/etc/xray'
local CONFIG_FILE = CONFIG_DIR .. '/config.json'
local AUTH_FILE   = CONFIG_DIR .. '/hop-auth'

-- ── URL helpers ───────────────────────────────────────────────────────────────

local function urldecode(s)
    return (s:gsub('+', ' '):gsub('%%(%x%x)', function(h)
        return string.char(tonumber(h, 16))
    end))
end

local function parse_qs(s)
    local t = {}
    for k, v in (s or ''):gmatch('([^&=]+)=([^&]*)') do
        t[urldecode(k)] = urldecode(v)
    end
    return t
end

local function html(s)
    return (s:gsub('&','&amp;'):gsub('<','&lt;'):gsub('>','&gt;'):gsub('"','&quot;'))
end

-- ── Multipart parser ──────────────────────────────────────────────────────────

local function parse_multipart(body, boundary)
    local parts = {}
    local first_delim = '--' .. boundary .. '\r\n'
    local delim = '\r\n--' .. boundary
    local pos = body:find(first_delim, 1, true)
    if not pos then return parts end
    pos = pos + #first_delim

    while true do
        local hdr_end = body:find('\r\n\r\n', pos, true)
        if not hdr_end then break end
        local headers = body:sub(pos, hdr_end - 1)
        local cstart  = hdr_end + 4
        local nd = body:find(delim, cstart, true)
        if not nd then break end
        local content = body:sub(cstart, nd - 1)
        local name  = headers:match(';%s*name="([^"]+)"')
        local fname = headers:match(';%s*filename="([^"]+)"')
        parts[#parts+1] = { name=name, filename=fname, content=content }
        if body:sub(nd + #delim, nd + #delim + 1) == '--' then break end
        pos = nd + #delim + 2
    end
    return parts
end

local function mp_field(parts, field_name)
    for _, p in ipairs(parts) do
        if p.name == field_name then return p.content end
    end
    return nil
end

-- ── VLESS parsing ─────────────────────────────────────────────────────────────

local function parse_vless(url)
    url = url:match('^%s*(.-)%s*$')
    if not url:match('^vless://') then error('Не VLESS URL (должен начинаться с vless://)', 0) end

    local rest = url:sub(9):gsub('#.*$', '')
    local uuid, tail = rest:match('^([^@]+)@(.+)$')
    if not uuid then error('Не удалось разобрать UUID и адрес', 0) end

    local hostport, params_str = tail:match('^([^?]+)%?(.*)$')
    if not hostport then hostport = tail; params_str = '' end

    local host, port = hostport:match('^(.+):(%d+)$')
    if not host then error('Не удалось разобрать host:port', 0) end

    local p = parse_qs(params_str)
    return {
        uuid     = uuid,
        host     = host,
        port     = tonumber(port),
        flow     = p.flow     or 'xtls-rprx-vision',
        network  = p.type     or 'tcp',
        security = p.security or 'reality',
        sni      = p.sni  or '',
        fp       = p.fp   or 'chrome',
        pbk      = p.pbk  or '',
        sid      = p.sid  or '',
    }
end

-- ── Creds from JSON file ──────────────────────────────────────────────────────

-- Извлечь параметры entry-hop из vless-outbound (как ep из parse_vless)
local function ep_from_outbound(ob)
    local v = ob.settings and ob.settings.vnext and ob.settings.vnext[1]
    if not v then error('В outbound нет settings.vnext', 0) end
    local u  = (v.users and v.users[1]) or {}
    local ss = ob.streamSettings or {}
    local rs = ss.realitySettings or {}
    return {
        uuid     = u.id,
        host     = v.address,
        port     = tonumber(v.port),
        flow     = u.flow or 'xtls-rprx-vision',
        network  = ss.network or 'tcp',
        security = ss.security or 'reality',
        sni      = rs.serverName  or '',
        fp       = rs.fingerprint or 'chrome',
        pbk      = rs.publicKey   or '',
        sid      = rs.shortId     or '',
    }
end

-- Разобрать JSON-конфиг Xray-клиента и достать креды entry-hop.
-- Приоритет outbound'а: proxy → exit-hop → первый vless.
local function parse_creds_from_json(content)
    local ok, cfg = pcall(cjson.decode, content)
    if not ok then error('Не удалось разобрать JSON: ' .. tostring(cfg), 0) end

    local chosen
    if cfg.outbounds then
        for _, ob in ipairs(cfg.outbounds) do
            if ob.protocol == 'vless' and (ob.tag == 'proxy' or ob.tag == 'exit-hop') then
                chosen = ob; break
            end
        end
        if not chosen then
            for _, ob in ipairs(cfg.outbounds) do
                if ob.protocol == 'vless' then chosen = ob; break end
            end
        end
    elseif cfg.protocol == 'vless' then
        chosen = cfg          -- файл — одиночный outbound
    end

    if not chosen then error('В JSON не найден vless-outbound', 0) end
    local ep = ep_from_outbound(chosen)
    if not ep.uuid then error('В кредах нет UUID (users[1].id)', 0) end
    if not ep.host or not ep.port then error('В кредах нет address/port', 0) end
    return ep
end

-- ── Pretty JSON encoder ───────────────────────────────────────────────────────

local _array_mt = getmetatable(cjson.decode('[]'))

local function _is_array(t)
    if _array_mt ~= nil then
        return getmetatable(t) == _array_mt
    end
    local n = 0
    for k in pairs(t) do
        if type(k) ~= 'number' or k ~= math.floor(k) then return false end
        n = n + 1
    end
    if n == 0 then return false end
    for i = 1, n do
        if t[i] == nil then return false end
    end
    return true
end

local function _str(s) return cjson.encode(s) end

local function pretty_json(val, level)
    level = level or 0
    local pad  = string.rep('  ', level)
    local pad1 = string.rep('  ', level + 1)

    if val == nil or val == cjson.null then
        return 'null'
    elseif type(val) == 'boolean' then
        return tostring(val)
    elseif type(val) == 'number' then
        return tostring(val)
    elseif type(val) == 'string' then
        return _str(val)
    elseif type(val) == 'table' then
        if _is_array(val) then
            if #val == 0 then return '[]' end
            local parts = {}
            for _, v in ipairs(val) do
                parts[#parts+1] = pad1 .. pretty_json(v, level + 1)
            end
            return '[\n' .. table.concat(parts, ',\n') .. '\n' .. pad .. ']'
        else
            local keys = {}
            for k in pairs(val) do keys[#keys+1] = k end
            if #keys == 0 then return '{}' end
            table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
            local parts = {}
            for _, k in ipairs(keys) do
                parts[#parts+1] = pad1 .. _str(tostring(k)) .. ': ' .. pretty_json(val[k], level + 1)
            end
            return '{\n' .. table.concat(parts, ',\n') .. '\n' .. pad .. '}'
        end
    end
    return 'null'
end

-- ── Config helpers ────────────────────────────────────────────────────────────

local function read_json(path)
    local f, err = io.open(path, 'r')
    if not f then error('Не удалось открыть ' .. path .. ': ' .. (err or ''), 0) end
    local s = f:read('*all'); f:close()
    return cjson.decode(s)
end

local function list_templates()
    local names = {}
    local p = io.popen('ls ' .. CONFIG_DIR .. '/config-*.json.bak 2>/dev/null')
    for line in p:lines() do
        local name = line:match('config%-(.+)%.json%.bak$')
        if name then names[#names+1] = name end
    end
    p:close()
    table.sort(names)
    return names
end

local function list_all_baks()
    local names = {}
    local p = io.popen('ls ' .. CONFIG_DIR .. '/*.json.bak 2>/dev/null')
    for line in p:lines() do
        local name = line:match('([^/]+)$')
        if name then names[#names+1] = name end
    end
    p:close()
    table.sort(names)
    return names
end

local function list_backups()
    local names = {}
    local p = io.popen('ls -r ' .. CONFIG_DIR .. '/config.json.20* 2>/dev/null')
    for line in p:lines() do
        local name = line:match('([^/]+)$')
        if name and name:match('^config%.json%.[0-9]+_[0-9]+$') then
            names[#names+1] = name
        end
    end
    p:close()
    return names
end

local function get_entry_hop_info(cfg)
    for _, ob in ipairs(cfg.outbounds or {}) do
        if ob.tag == 'entry-hop' then
            local v  = ob.settings.vnext[1]
            local rs = (ob.streamSettings or {}).realitySettings or {}
            return {
                host = v.address,
                port = v.port,
                sni  = rs.serverName or '',
                sid  = rs.shortId    or '',
            }
        end
    end
    return nil
end

local function get_proxy_info(cfg)
    for _, ob in ipairs(cfg.outbounds or {}) do
        if ob.tag == 'proxy' or ob.tag == 'exit-hop' then
            local v  = ob.settings and ob.settings.vnext and ob.settings.vnext[1]
            if not v then return nil end
            local rs = (ob.streamSettings or {}).realitySettings or {}
            local dp = ((ob.streamSettings or {}).sockopt or {}).dialerProxy
            return {
                host        = v.address,
                port        = v.port,
                sni         = rs.serverName or '',
                sid         = rs.shortId    or '',
                dialerProxy = dp,            -- есть → цепочка через entry-hop (2 хопа)
            }
        end
    end
    return nil
end

local function get_active_template(cfg)
    local exit_addr
    for _, ob in ipairs(cfg.outbounds or {}) do
        if ob.tag == 'proxy' or ob.tag == 'exit-hop' then
            exit_addr = ob.settings.vnext[1].address
            break
        end
    end
    if not exit_addr then return nil end
    for _, name in ipairs(list_templates()) do
        local ok, tpl = pcall(read_json, CONFIG_DIR..'/config-'..name..'.json.bak')
        if ok then
            for _, ob in ipairs(tpl.outbounds or {}) do
                if ob.tag == 'proxy' or ob.tag == 'exit-hop' then
                    if ob.settings.vnext[1].address == exit_addr then
                        return name
                    end
                end
            end
        end
    end
    return nil
end

-- Бэкап config.json → config.json.YYYYMMDD_HHMMSS, возвращает имя бэкапа
local function backup_config()
    local fb = io.open(CONFIG_FILE, 'r')
    if not fb then return '' end
    fb:close()
    local ts  = os.date('%Y%m%d_%H%M%S')
    local bak = CONFIG_FILE .. '.' .. ts
    os.rename(CONFIG_FILE, bak)
    return 'config.json.' .. ts
end

-- Валидация через xray -test, возвращает ok, вывод
local function xray_validate(tmp_path)
    local cmd = io.popen('/usr/bin/xray run -test -config ' .. tmp_path .. ' 2>&1')
    local out  = cmd:read('*all')
    local ok   = cmd:close()
    return (ok and out:find('Configuration OK') ~= nil), out
end

-- ── Geo-файлы (geoip.dat / geosite.dat / geosite-v2fly.dat) ───────────────────

-- key → имя файла в asset-каталоге + URL источника
local GEO = {
    ['geoip'] = {
        file = 'geoip.dat',
        url  = 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat',
        src  = 'Loyalsoldier',
    },
    ['geosite'] = {
        file = 'geosite.dat',
        url  = 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat',
        src  = 'Loyalsoldier',
    },
    ['geosite-v2fly'] = {
        file = 'geosite-v2fly.dat',
        url  = 'https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat',
        src  = 'v2fly dlc',
    },
}
local GEO_ORDER = { 'geoip', 'geosite', 'geosite-v2fly' }
local GEO_MIN   = 100000   -- меньше — точно битая закачка/HTML-ошибка

local function file_size(path)
    local f = io.open(path, 'rb')
    if not f then return nil end
    local sz = f:seek('end')
    f:close()
    return sz
end

local function xray_running()
    local p = io.popen('pidof xray 2>/dev/null')
    local out = p and p:read('*all') or ''
    if p then p:close() end
    return out:match('%d') ~= nil
end

-- ── Proxy on/off toggle (если на роутере есть proxy-toggle.sh) ─────────────────

local TOGGLE_SCRIPT = '/etc/xray/proxy-toggle.sh'
local DISABLED_FLAG = '/etc/xray/disabled'

local function toggle_available()
    local f = io.open(TOGGLE_SCRIPT, 'r')
    if f then f:close(); return true end
    return false
end

local function proxy_disabled()
    local f = io.open(DISABLED_FLAG, 'r')
    if f then f:close(); return true end
    return false
end

local function proxy_toggle(state)
    if state ~= 'on' and state ~= 'off' then error('Недопустимое состояние', 0) end
    if not toggle_available() then error('На роутере нет ' .. TOGGLE_SCRIPT, 0) end
    local p = io.popen(TOGGLE_SCRIPT .. ' ' .. state .. ' 2>&1')
    local out = p:read('*all')
    p:close()
    return out
end

-- asset-каталог xray (uci xray.config.datadir, дефолт /usr/share/xray)
local function asset_dir()
    local p = io.popen('uci -q get xray.config.datadir 2>/dev/null')
    local d = p and p:read('*l') or nil
    if p then p:close() end
    if d and d:match('%S') then return (d:match('^%s*(.-)%s*$')) end
    return '/usr/share/xray'
end

-- xray -test текущего config.json с явным asset-каталогом (грузит .dat оттуда)
local function geo_validate(dir)
    local cmd = 'XRAY_LOCATION_ASSET=' .. dir ..
                ' /usr/bin/xray run -test -config ' .. CONFIG_FILE .. ' 2>&1'
    local c = io.popen(cmd)
    local out = c:read('*all')
    c:close()
    return (out:find('Configuration OK') ~= nil), out
end

-- Скачать → бэкап(.bak) → подмена → xray -test → рестарт; при ошибке откат.
-- Перезапускает xray ТОЛЬКО если он уже работал (иначе уважает выключенный
-- прокси, напр. /etc/xray/proxy-toggle.sh off). Возвращает: размер, статус-строку
-- ('restarted' | 'restart_failed' | 'stopped').
local function update_geo(key)
    local g = GEO[key]
    if not g then error('Неизвестный geo-файл', 0) end

    local was_running = xray_running()
    local dir  = asset_dir()
    local dest = dir .. '/' .. g.file
    local newf = dir .. '/.' .. g.file .. '.new'   -- тот же fs → атомарный rename
    local bakf = dir .. '/' .. g.file .. '.bak'

    os.remove(newf)
    local cmd = string.format(
        'curl -fL --connect-timeout 20 --max-time 180 -o %q %q 2>&1', newf, g.url)
    local p = io.popen(cmd)
    local cout = p:read('*all')
    p:close()

    local sz = file_size(newf)
    if not sz or sz < GEO_MIN then
        os.remove(newf)
        error('Скачивание не удалось (размер: ' .. tostring(sz) .. ').\n' ..
              (cout ~= '' and cout:sub(1, 300) or 'нет вывода curl'), 0)
    end

    -- подмена с бэкапом старого
    local had_old = file_size(dest) ~= nil
    if had_old then os.rename(dest, bakf) end
    os.rename(newf, dest)

    -- валидация на текущем конфиге
    local ok, out = geo_validate(dir)
    if not ok then
        os.remove(dest)
        if had_old then os.rename(bakf, dest) end   -- откат
        error('Новый ' .. g.file .. ' не прошёл xray -test — откат:\n' .. out, 0)
    end

    if not was_running then
        return sz, 'stopped'   -- прокси выключен — не поднимаем, файл применится при старте
    end
    local rc = os.execute('/etc/init.d/xray restart >/dev/null 2>&1')
    return sz, ((rc == 0 or rc == true) and xray_running()) and 'restarted' or 'restart_failed'
end

-- ── Управляемые списки доменов ───────────────────────────────────────────────
--
-- Панель НЕ создаёт собственных правил. Домены живут в двух УЖЕ СУЩЕСТВУЮЩИХ
-- правилах routing.rules, помеченных ruleTag:
--   hop-list-foreign — «заграничный» список (telegram/claude/openai/linkedin…)
--   hop-list-ru      — «российский» список (asna/yandex/vk/банки…)
--
-- Правится ТОЛЬКО поле domain этих правил. outboundTag, позиция и всё остальное
-- принадлежат конфигу: куда ведёт лейн — решает сам конфиг. В прямом режиме
-- foreign → proxy, ru → direct (или entry-hop); в обратном (роутер за границей,
-- выход в РФ) foreign → direct, ru → proxy. Поэтому один и тот же список
-- безопасно раскатывать на весь флот.
--
-- Если меток ещё нет, они проставляются автоматически по якорным доменам
-- (ANCHORS), а устаревшие правила hop-ui-proxy / hop-ui-direct (панель ставила
-- их первыми и они перекрывали нижние списки) вливаются в свой лейн и удаляются.

local LANES      = { 'foreign', 'ru' }
local RULE_TAG   = { foreign = 'hop-list-foreign', ru = 'hop-list-ru' }
local LEGACY_TAG = { ['hop-ui-proxy'] = 'foreign', ['hop-ui-direct'] = 'ru' }
local LANE_TITLE = { foreign = 'заграничный', ru = 'российский' }
local ANCHORS    = {
    foreign = { 'telegram.org', 't.me', 'claude.ai', 'openai.com', 'chatgpt.com', 'signal.org' },
    ru      = { 'asna.pro', 'yandex.ru', 'ya.ru', 'vk.com', 'gosuslugi.ru', 'ozon.ru' },
}
local ANCHOR_MIN = 2      -- столько якорей нужно, чтобы опознать список

-- Префиксы Xray, которые пропускаем как есть; всё прочее получает domain:
local KNOWN_PREFIX = {
    ['domain:'] = true, ['full:']    = true, ['regexp:'] = true,
    ['keyword:'] = true, ['geosite:'] = true, ['ext:']    = true,
}

-- Строка → элемент domain-списка. nil = строку пропустить (пусто/комментарий).
local function normalize_domain(line)
    local s = line:match('^%s*(.-)%s*$')
    if s == '' or s:sub(1, 1) == '#' then return nil end
    s = s:gsub('^%a+://', ''):gsub('/.*$', '')          -- вставили URL — берём хост
    local pfx = s:match('^(%a+:)')
    if pfx and KNOWN_PREFIX[pfx:lower()] then
        local rest = s:sub(#pfx + 1)
        if rest == '' then error('Пустое значение после ' .. pfx, 0) end
        return pfx:lower() .. rest
    end
    if s:find('%.') and s:match('^[%w%*%._%-]+$') then
        return 'domain:' .. s:lower()
    end
    error('Не похоже на домен: ' .. s, 0)
end

-- Текст из textarea → массив доменов (нормализованных, без дублей, в порядке ввода)
local function parse_list(text)
    local out, seen = {}, {}
    for line in (text or ''):gmatch('[^\r\n]+') do
        local d = normalize_domain(line)
        if d and not seen[d] then seen[d] = true; out[#out + 1] = d end
    end
    return out
end

-- 'domain:vk.com' → 'vk.com' (для сравнения с якорями)
local function bare(d)
    return (tostring(d):gsub('^%a+:', ''))
end

-- Найти правила-лейны. Возвращает: map lane→rule, список legacy-правил,
-- migrated (true, если пришлось проставить метки).
local function locate_lanes(cfg)
    local rules = ((cfg.routing or {}).rules) or {}
    local found, legacy, migrated = {}, {}, false

    for _, r in ipairs(rules) do
        if type(r) == 'table' and type(r.ruleTag) == 'string' then
            for _, lane in ipairs(LANES) do
                if r.ruleTag == RULE_TAG[lane] and type(r.domain) == 'table' then
                    found[lane] = r
                end
            end
            if LEGACY_TAG[r.ruleTag] and type(r.domain) == 'table' then
                legacy[#legacy + 1] = r
            end
        end
    end

    for _, lane in ipairs(LANES) do
        if not found[lane] then
            local best, best_hits = nil, 0
            for _, r in ipairs(rules) do
                if type(r) == 'table' and type(r.domain) == 'table' and r.ruleTag == nil then
                    local set = {}
                    for _, d in ipairs(r.domain) do set[bare(d)] = true end
                    local hits = 0
                    for _, a in ipairs(ANCHORS[lane]) do if set[a] then hits = hits + 1 end end
                    if hits > best_hits then best, best_hits = r, hits end
                end
            end
            if best and best_hits >= ANCHOR_MIN then
                best.ruleTag = RULE_TAG[lane]
                found[lane]  = best
                migrated     = true
            end
        end
    end

    return found, legacy, migrated
end

-- Влить устаревшие hop-ui-* правила в свои лейны и удалить их.
-- Возвращает число перенесённых доменов и число удалённых правил.
local function fold_legacy(cfg, found, legacy)
    if #legacy == 0 then return 0, 0 end
    local moved, killed = 0, 0
    local drop = {}
    for _, r in ipairs(legacy) do
        local lane = LEGACY_TAG[r.ruleTag]
        local dst  = found[lane]
        if dst then
            local seen = {}
            for _, d in ipairs(dst.domain) do seen[d] = true end
            for _, d in ipairs(r.domain) do
                if not seen[d] then seen[d] = true; dst.domain[#dst.domain + 1] = d; moved = moved + 1 end
            end
            drop[r] = true; killed = killed + 1
        end
    end
    if killed > 0 then
        local kept = {}
        for _, r in ipairs(cfg.routing.rules) do
            if not drop[r] then kept[#kept + 1] = r end
        end
        cfg.routing.rules = kept
    end
    return moved, killed
end

-- Текущий список лейна
local function get_lane(cfg, lane)
    local found = locate_lanes(cfg)
    local out = {}
    if found[lane] then
        for _, d in ipairs(found[lane].domain) do out[#out + 1] = d end
    end
    return out
end

-- Сколько доменов лейна перекрыто правилом, стоящим ВЫШЕ (first-match-wins).
local function count_shadowed(cfg, found, lane)
    local target = found[lane]
    if not target then return 0 end
    local mine = {}
    for _, d in ipairs(target.domain) do mine[d] = true end
    local n = 0
    for _, r in ipairs(cfg.routing.rules) do
        if r == target then break end
        if type(r) == 'table' and type(r.domain) == 'table' then
            for _, d in ipairs(r.domain) do if mine[d] then n = n + 1 end end
        end
    end
    return n
end

-- Применить списки к одному файлу. mode: 'merge' | 'replace'.
-- Возвращает: status ('ok'|'nochange'|'nolist'|'broken'|'fail'),
--             добавлено, перенесено из legacy, перекрыто сверху, вывод xray
local function write_lists(path, lists, mode, bakdir)
    local ok_read, cfg = pcall(read_json, path)
    if not ok_read then return 'fail', 0, 0, 0, tostring(cfg) end

    local found, legacy, migrated = locate_lanes(cfg)
    local moved, killed = fold_legacy(cfg, found, legacy)
    local changed = migrated or killed > 0

    for _, lane in ipairs(LANES) do
        if #(lists[lane] or {}) > 0 and not found[lane] then
            return 'nolist', 0, 0, 0, 'нет правила ' .. RULE_TAG[lane] ..
                   ' и не опознан ' .. LANE_TITLE[lane] .. ' список'
        end
    end

    local added, shadowed = 0, 0
    for _, lane in ipairs(LANES) do
        local rule = found[lane]
        if rule then
            local cur = rule.domain
            local new
            if mode == 'replace' then
                new = lists[lane]
            else
                new = {}
                local seen = {}
                for _, d in ipairs(cur) do
                    if not seen[d] then seen[d] = true; new[#new + 1] = d end
                end
                for _, d in ipairs(lists[lane] or {}) do
                    if not seen[d] then
                        seen[d] = true; new[#new + 1] = d; added = added + 1
                    end
                end
            end
            if #new ~= #cur then changed = true
            else
                for i = 1, #new do if new[i] ~= cur[i] then changed = true; break end end
            end
            rule.domain = new
        end
    end

    for _, lane in ipairs(LANES) do
        shadowed = shadowed + count_shadowed(cfg, found, lane)
    end

    if not changed then return 'nochange', 0, 0, shadowed, '' end

    local tmp = CONFIG_DIR .. '/.config-validate.json'
    local f, ferr = io.open(tmp, 'w')
    if not f then return 'fail', 0, 0, 0, tostring(ferr) end
    f:write(pretty_json(cfg)); f:write('\n'); f:close()

    local valid, out = xray_validate(tmp)
    if not valid then
        -- был ли файл валиден ДО нас? если нет — это не наша поломка
        local was_ok = xray_validate(path)
        os.remove(tmp)
        return (was_ok and 'fail' or 'broken'), 0, 0, 0, out
    end

    if path == CONFIG_FILE then
        backup_config()                       -- config.json.TS — виден в «Восстановить»
    elseif bakdir then
        os.execute('mkdir -p ' .. bakdir .. ' && cp ' .. path .. ' ' .. bakdir .. '/ 2>/dev/null')
    end
    os.rename(tmp, path)
    return 'ok', added, moved, shadowed, ''
end

-- Раскатать списки по выбранным целям. targets: {config=bool, templates=bool}
-- Возвращает таблицу-отчёт.
local function apply_lists(lists, mode, targets)
    local files = {}
    if targets.config then files[#files + 1] = CONFIG_FILE end
    if targets.templates then
        for _, name in ipairs(list_templates()) do
            files[#files + 1] = CONFIG_DIR .. '/config-' .. name .. '.json.bak'
        end
    end
    if #files == 0 then error('Не выбрано ни одной цели', 0) end

    -- каталог создаётся лениво, при первом реальном бэкапе шаблона
    local bakdir = CONFIG_DIR .. '/backups/' .. os.date('%Y%m%d_%H%M%S') .. '-lists'

    local rep = { ok = {}, nochange = {}, nolist = {}, broken = {}, fail = {},
                  bakdir = bakdir, added = 0, moved = 0, shadowed = 0, restarted = nil }
    local config_changed = false

    for _, path in ipairs(files) do
        local name = path:match('([^/]+)$')
        local st, added, moved, shadowed, out = write_lists(path, lists, mode, bakdir)
        rep.added    = rep.added + added
        rep.moved    = rep.moved + moved
        rep.shadowed = rep.shadowed + shadowed
        if st == 'ok' then
            rep.ok[#rep.ok + 1] = name
            if path == CONFIG_FILE then config_changed = true end
        elseif st == 'nochange' then
            rep.nochange[#rep.nochange + 1] = name
        elseif st == 'nolist' then
            rep.nolist[#rep.nolist + 1] = name
        elseif st == 'broken' then
            rep.broken[#rep.broken + 1] = name
        else
            rep.fail[#rep.fail + 1] = name .. ': ' .. (out:match('Main: (.+)') or out:sub(1, 200))
        end
    end

    -- рестарт только если поменялся активный конфиг и xray работал
    if config_changed then
        if xray_running() then
            rep.restarted = (os.execute('/etc/init.d/xray restart >/dev/null 2>&1') == 0)
        else
            rep.restarted = 'stopped'
        end
    end
    return rep
end

-- ── Apply (шаблон + entry-hop) ────────────────────────────────────────────────

local function apply(template_name, ep)
    local cfg = read_json(CONFIG_DIR .. '/config-' .. template_name .. '.json.bak')

    local entry_ob = {
        tag      = 'entry-hop',
        protocol = 'vless',
        settings = { vnext = {{
            address = ep.host,
            port    = ep.port,
            users   = {{ id = ep.uuid, flow = ep.flow, encryption = 'none' }}
        }}},
        streamSettings = {
            network  = ep.network,
            security = ep.security,
            realitySettings = {
                serverName  = ep.sni,
                fingerprint = ep.fp,
                publicKey   = ep.pbk,
                shortId     = ep.sid,
            }
        }
    }

    local found = false
    for i, ob in ipairs(cfg.outbounds) do
        if ob.tag == 'entry-hop' then
            cfg.outbounds[i] = entry_ob; found = true; break
        end
    end
    if not found then cfg.outbounds[#cfg.outbounds + 1] = entry_ob end

    for _, ob in ipairs(cfg.outbounds) do
        if ob.tag == 'proxy' or ob.tag == 'exit-hop' then
            ob.streamSettings = ob.streamSettings or {}
            ob.streamSettings.sockopt = ob.streamSettings.sockopt or {}
            ob.streamSettings.sockopt.dialerProxy = 'entry-hop'
            break
        end
    end

    local tmp = CONFIG_DIR .. '/.config-validate.json'
    local f = assert(io.open(tmp, 'w'))
    f:write(pretty_json(cfg)); f:write('\n'); f:close()

    local ok, out = xray_validate(tmp)
    if not ok then
        os.remove(tmp)
        error('Xray отверг конфиг:\n' .. out, 0)
    end

    local bak = backup_config()
    os.rename(tmp, CONFIG_FILE)
    local rc = os.execute('/etc/init.d/xray restart >/dev/null 2>&1')
    return rc == 0, bak
end

-- ── Direct copy (прямая замена без обработки) ────────────────────────────────

local function direct_copy(bak_name)
    if bak_name:find('[/\\]') or not bak_name:match('%.json%.bak$') then
        error('Недопустимое имя файла', 0)
    end
    local src = CONFIG_DIR .. '/' .. bak_name
    local fin, ferr = io.open(src, 'r')
    if not fin then error('Файл не найден: ' .. (ferr or bak_name), 0) end
    local content = fin:read('*all'); fin:close()

    local tmp = CONFIG_DIR .. '/.config-validate.json'
    local fout = assert(io.open(tmp, 'w'))
    fout:write(content); fout:close()

    local ok, out = xray_validate(tmp)
    if not ok then
        os.remove(tmp)
        error('Xray отверг конфиг:\n' .. out, 0)
    end

    local bak = backup_config()
    os.rename(tmp, CONFIG_FILE)
    os.execute('/etc/init.d/xray restart >/dev/null 2>&1')
    return bak
end

-- ── Restore backup ───────────────────────────────────────────────────────────

local function restore_backup(backup_name)
    if not backup_name:match('^config%.json%.[0-9]+_[0-9]+$') then
        error('Недопустимое имя файла', 0)
    end
    local src = CONFIG_DIR .. '/' .. backup_name
    local fin, ferr = io.open(src, 'r')
    if not fin then error('Файл не найден: ' .. (ferr or backup_name), 0) end
    local content = fin:read('*all'); fin:close()

    local tmp = CONFIG_DIR .. '/.config-validate.json'
    local fout = assert(io.open(tmp, 'w'))
    fout:write(content); fout:close()

    local ok, out = xray_validate(tmp)
    if not ok then
        os.remove(tmp)
        error('Xray отверг конфиг:\n' .. out, 0)
    end

    local bak = backup_config()
    os.rename(tmp, CONFIG_FILE)
    os.execute('/etc/init.d/xray restart >/dev/null 2>&1')
    return bak
end

-- ── Flash message (Post/Redirect/Get) ────────────────────────────────────────

local FLASH_FILE = '/tmp/hop-flash-msg'

local function flash_save(msg)
    local f = io.open(FLASH_FILE, 'w')
    if f then f:write(msg); f:close() end
end

local function flash_read()
    local f = io.open(FLASH_FILE, 'r')
    if not f then return nil end
    local msg = f:read('*all'); f:close()
    os.remove(FLASH_FILE)
    return msg ~= '' and msg or nil
end

local function redirect_back()
    local script = os.getenv('SCRIPT_NAME') or '/cgi-bin/update-hop'
    io.write('Status: 302 Found\r\n')
    io.write('Location: ' .. script .. '\r\n\r\n')
end

-- ── Upload file ───────────────────────────────────────────────────────────────

local function upload_file(content, savename)
    if not savename or savename == '' then error('Укажи имя файла', 0) end
    if savename:find('[/\\]') then error('Недопустимое имя файла', 0) end
    if not savename:match('%.bak$') then savename = savename .. '.bak' end
    if not savename:match('%.json%.bak$') then
        error('Имя файла должно заканчиваться на .json.bak (получилось: ' .. savename .. ')', 0)
    end

    local tmp = CONFIG_DIR .. '/.upload-validate.json'
    local f, err = io.open(tmp, 'w')
    if not f then error('Не удалось записать файл: ' .. (err or ''), 0) end
    f:write(content); f:close()

    local ok, out = xray_validate(tmp)
    if not ok then
        os.remove(tmp)
        return false, savename, out
    end

    os.rename(tmp, CONFIG_DIR .. '/' .. savename)
    return true, savename, out
end

-- ── Auth ─────────────────────────────────────────────────────────────────────

local function b64decode(s)
    local chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    local map = {}
    for i = 1, #chars do map[chars:sub(i, i)] = i - 1 end
    s = s:gsub('[^A-Za-z0-9+/]', '')
    local out = {}
    for i = 1, #s, 4 do
        local a = map[s:sub(i,   i  )] or 0
        local b = map[s:sub(i+1, i+1)] or 0
        local c = map[s:sub(i+2, i+2)]
        local d = map[s:sub(i+3, i+3)]
        out[#out+1] = string.char(a * 4 + math.floor(b / 16))
        if c then out[#out+1] = string.char((b % 16) * 16 + math.floor(c / 4)) end
        if d then out[#out+1] = string.char((c % 4) * 64 + d) end
    end
    return table.concat(out)
end

local function check_auth()
    local header = os.getenv('HTTP_AUTHORIZATION') or ''
    local token  = header:match('^Basic%s+(%S+)$')
    if not token then return false end
    local creds = b64decode(token)
    local f = io.open(AUTH_FILE, 'r')
    if not f then return false end
    local stored = (f:read('*l') or ''):match('^%s*(.-)%s*$')
    f:close()
    return creds == stored
end

-- ── HTML ──────────────────────────────────────────────────────────────────────

local CSS = [[
body{font-family:monospace;max-width:660px;margin:40px auto;padding:0 16px;
     background:#0f172a;color:#cbd5e1}
h2{color:#a78bfa;margin-bottom:4px}
.sub{color:#64748b;font-size:12px;margin-bottom:20px}
.card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:16px;margin:14px 0}
.lbl{color:#64748b;font-size:11px;text-transform:uppercase;letter-spacing:.05em}
.val{color:#e2e8f0}
select,textarea,input[type=text]{width:100%;box-sizing:border-box;background:#0f172a;
  color:#e2e8f0;border:1px solid #475569;border-radius:6px;padding:9px;font-size:13px;
  font-family:monospace;margin-top:6px}
select{cursor:pointer}textarea{resize:vertical}
input[type=file]{display:block;margin-top:8px;color:#94a3b8;font-size:13px;
  font-family:monospace;width:100%}
input[type=file]::file-selector-button{background:#334155;color:#e2e8f0;border:none;
  border-radius:4px;padding:6px 14px;cursor:pointer;margin-right:10px;font-family:monospace}
button{background:#7c3aed;color:#fff;border:none;border-radius:6px;
  padding:10px 26px;font-size:14px;cursor:pointer;margin-top:10px}
button:hover{background:#6d28d9}
.ok{color:#34d399;border-color:#34d399}.err{color:#f87171;border-color:#f87171}
.msg{border:1px solid;border-radius:6px;padding:10px 14px;margin:12px 0}
.none{color:#475569;font-style:italic}
.bak{color:#94a3b8;font-size:11px;margin-top:4px}
code{background:#0f172a;border-radius:3px;padding:2px 5px;font-size:12px;color:#fbbf24}
]]

local function render(message, sel_tpl, vless_pre, sel_bak, sel_restore)
    local ok, cfg = pcall(read_json, CONFIG_FILE)
    local cur_html, active

    if ok then
        local entry = get_entry_hop_info(cfg)
        local prox  = get_proxy_info(cfg)
        active = get_active_template(cfg)
        if entry then
            -- 2 хопа: entry-hop → exit
            local exit_part = prox and string.format(
                ' &nbsp;→&nbsp; <span class="lbl">exit</span> <span class="val">%s</span>',
                html(prox.host)) or ''
            cur_html = string.format(
                '<span class="ok">2 хопа</span> &nbsp;<span class="lbl">entry</span> '..
                '<span class="val">%s:%s</span> &nbsp;<span class="lbl">sni</span> '..
                '<span class="val">%s</span>%s',
                html(entry.host), entry.port, html(entry.sni), exit_part
            )
        elseif prox then
            -- 1 хоп: прямое подключение к proxy-серверу (entry-hop нет)
            cur_html = string.format(
                '<span class="val">1 хоп (прямое)</span> &nbsp;<span class="lbl">сервер</span> '..
                '<span class="val">%s:%s</span> &nbsp;<span class="lbl">sni</span> '..
                '<span class="val">%s</span>',
                html(prox.host), prox.port, html(prox.sni)
            )
        else
            cur_html = '<span class="none">прокси-outbound не найден</span>'
        end
    else
        cur_html = '<span class="err">Ошибка чтения config.json</span>'
    end

    -- Dropdown шаблонов (entry-hop форма)
    local opts = ''
    for _, name in ipairs(list_templates()) do
        local s = (name == (sel_tpl or active)) and ' selected' or ''
        local label = name
        local ok_t, tpl = pcall(read_json, CONFIG_DIR..'/config-'..name..'.json.bak')
        if ok_t then
            for _, ob in ipairs(tpl.outbounds or {}) do
                if ob.tag == 'proxy' or ob.tag == 'exit-hop' then
                    local addr = ob.settings and ob.settings.vnext
                                 and ob.settings.vnext[1] and ob.settings.vnext[1].address
                    if addr then label = name .. '  (' .. addr .. ')' end
                    break
                end
            end
        end
        opts = opts .. string.format('<option value="%s"%s>%s</option>', html(name), s, html(label))
    end
    if opts == '' then opts = '<option value="">— нет шаблонов в /etc/xray/ —</option>' end

    local active_badge = active
        and string.format(' &nbsp;<span class="lbl">шаблон:</span> <span class="val">%s</span>', html(active))
        or ''

    -- Dropdown всех .json.bak (прямая замена)
    local bak_opts = ''
    for _, name in ipairs(list_all_baks()) do
        local s = (name == sel_bak) and ' selected' or ''
        bak_opts = bak_opts .. string.format('<option value="%s"%s>%s</option>', html(name), s, html(name))
    end
    if bak_opts == '' then bak_opts = '<option value="">— нет .json.bak файлов —</option>' end

    -- Dropdown бэкапов (восстановление)
    local restore_opts = ''
    for _, name in ipairs(list_backups()) do
        local s = (name == sel_restore) and ' selected' or ''
        restore_opts = restore_opts .. string.format('<option value="%s"%s>%s</option>', html(name), s, html(name))
    end
    if restore_opts == '' then restore_opts = '<option value="">— нет бэкапов —</option>' end

    -- Управляемые списки доменов (карточка «Списки доменов»)
    local lst  = { foreign = {}, ru = {} }
    local lane_to = { foreign = '—', ru = '—' }
    if ok then
        local found = locate_lanes(cfg)
        for _, lane in ipairs(LANES) do
            local r = found[lane]
            if r then
                for _, d in ipairs(r.domain) do lst[lane][#lst[lane] + 1] = d end
                lane_to[lane] = r.outboundTag or ('balancer:' .. tostring(r.balancerTag)) or '—'
            end
        end
    end
    local n_tpl = #list_templates()
    local lists_html = string.format([[
<div class="card">
  <form method="POST">
    <input type="hidden" name="action" value="rules">
    <div class="lbl">Списки доменов &nbsp;<span class="bak">правила <code>hop-list-foreign</code> / <code>hop-list-ru</code></span></div>
    <div style="margin-top:12px">
      <div class="lbl">Заграничные ресурсы <span class="bak">(%s доменов · в этом конфиге → <code>%s</code>)</span></div>
      <textarea name="list_foreign" rows="7" placeholder="linkedin.com">%s</textarea>
    </div>
    <div style="margin-top:12px">
      <div class="lbl">Российские ресурсы <span class="bak">(%s доменов · в этом конфиге → <code>%s</code>)</span></div>
      <textarea name="list_ru" rows="7" placeholder="vkvideo.ru">%s</textarea>
    </div>
    <div style="margin-top:14px;display:flex;gap:18px;flex-wrap:wrap">
      <label><input type="radio" name="mode" value="merge" checked> добавить</label>
      <label><input type="radio" name="mode" value="replace"> заменить целиком</label>
    </div>
    <div style="margin-top:8px;display:flex;gap:18px;flex-wrap:wrap">
      <label><input type="checkbox" name="t_config" value="1" checked> config.json</label>
      <label><input type="checkbox" name="t_templates" value="1" checked> все шаблоны (%s)</label>
    </div>
    <div class="bak" style="margin-top:10px">Домен на строку · <code>#</code> — комментарий · голый домен станет
    <code>domain:</code>, префиксы <code>full: regexp: keyword: geosite: ext:</code> идут как есть.<br>
    Домены дописываются в СУЩЕСТВУЮЩИЕ правила-списки; куда ведёт лейн (<code>proxy</code>,
    <code>direct</code>, <code>entry-hop</code>) решает сам конфиг — панель outboundTag и порядок правил не трогает.<br>
    Каждый файл проверяется <code>xray -test</code>, бэкапы в <code>/etc/xray/backups/</code>.</div>
    <button type="submit">Сохранить списки</button>
  </form>
</div>]],
        #lst.foreign, html(lane_to.foreign), html(table.concat(lst.foreign, '\n')),
        #lst.ru,      html(lane_to.ru),      html(table.concat(lst.ru,      '\n')),
        n_tpl)

    -- Geo-файлы: строка на каждый файл (имя · размер · кнопка)
    local gdir = asset_dir()
    local geo_rows = ''
    for _, key in ipairs(GEO_ORDER) do
        local g  = GEO[key]
        local sz = file_size(gdir .. '/' .. g.file)
        local sz_txt = sz and string.format('%.2f МБ', sz / 1048576) or '— нет файла —'
        geo_rows = geo_rows .. string.format([[
    <div style="display:flex;justify-content:space-between;align-items:center;margin:10px 0">
      <span class="val">%s &nbsp;<span class="bak">%s · %s</span></span>
      <form method="POST" style="margin:0">
        <input type="hidden" name="action" value="geo">
        <input type="hidden" name="geo_file" value="%s">
        <button type="submit" style="margin:0;padding:6px 16px">Обновить</button>
      </form>
    </div>]], html(g.file), sz_txt, html(g.src), html(key))
    end

    -- Карточка вкл/выкл прокси — только если есть proxy-toggle.sh
    local toggle_html = ''
    if toggle_available() then
        local is_off   = proxy_disabled()
        local running  = xray_running()
        local state_txt = is_off
            and '<span class="err">OFF</span>'
            or  '<span class="ok">ON</span>'
        local proc_txt = running and 'running' or 'stopped'
        toggle_html = string.format([[
<div class="card">
  <div class="lbl">Xray-клиент (прокси)</div>
  <div style="margin-top:6px">Состояние: <b>%s</b> &nbsp;<span class="lbl">процесс</span> <span class="val">%s</span></div>
  <div style="display:flex;gap:10px;margin-top:12px">
    <form method="POST" style="margin:0;flex:1">
      <input type="hidden" name="action" value="toggle">
      <input type="hidden" name="toggle_state" value="on">
      <button type="submit" style="margin:0;width:100%%">Включить</button>
    </form>
    <form method="POST" style="margin:0;flex:1">
      <input type="hidden" name="action" value="toggle">
      <input type="hidden" name="toggle_state" value="off">
      <button type="submit" style="margin:0;width:100%%;background:#92400e">Выключить</button>
    </form>
  </div>
  <div class="bak" style="margin-top:10px">on: запуск xray + автозапуск + прозрачный прокси · off: остановка + снятие NAT + флаг <code>/etc/xray/disabled</code> (переживает перезагрузку)</div>
</div>]], state_txt, proc_txt)
    end

    return string.format([[Content-Type: text/html; charset=utf-8

<!DOCTYPE html>
<html lang="ru">
<head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Xray Hop Updater</title>
<style>%s</style></head>
<body>
<h2>Xray Hop Updater</h2>
<div class="sub">GL.iNet · порт 8888</div>

<div class="card">
  <div class="lbl">Подключение сейчас%s</div>
  <div style="margin-top:6px">%s</div>
</div>
%s
%s

<div class="card">
  <form method="POST" enctype="multipart/form-data">
    <input type="hidden" name="action" value="hop">
    <div class="lbl">Шаблон (выходной хоп)</div>
    <select name="template">%s</select>
    <div style="margin-top:14px">
      <div class="lbl">Entry-hop — вставь vless://</div>
      <textarea name="vless_url" rows="4"
        placeholder="vless://UUID@HOST:PORT?encryption=none&amp;flow=xtls-rprx-vision&amp;type=tcp&amp;security=reality&amp;sni=…&amp;fp=chrome&amp;pbk=…&amp;sid=…"
      ></textarea>
    </div>
    <div class="bak" style="text-align:center;margin:12px 0;color:#64748b">— или —</div>
    <div>
      <div class="lbl">Вставь JSON с кредами entry-hop</div>
      <textarea name="creds_json" rows="5"
        placeholder='{ "outbounds": [ { "tag": "proxy", "protocol": "vless", "settings": { "vnext": [ … ] }, "streamSettings": { … } } ] }'
      ></textarea>
    </div>
    <div class="bak" style="text-align:center;margin:12px 0;color:#64748b">— или —</div>
    <div>
      <div class="lbl">Загрузи JSON-файл с кредами entry-hop</div>
      <input type="file" name="creds_file" accept=".json,.txt">
    </div>
    <div class="bak" style="margin-top:8px">Берётся outbound <code>proxy</code> (или первый vless). Приоритет: файл → JSON-текст → vless://</div>
    <button type="submit">Применить и перезапустить Xray</button>
  </form>
</div>

%s

<div class="card">
  <form method="POST">
    <input type="hidden" name="action" value="copy">
    <div class="lbl">Прямая замена конфига (без обработки)</div>
    <select name="bak_name" style="margin-top:8px">%s</select>
    <div class="bak">Конфиг применяется как есть — без подстановки entry-hop</div>
    <button type="submit">Применить напрямую</button>
  </form>
</div>

<div class="card">
  <form method="POST" enctype="multipart/form-data">
    <input type="hidden" name="action" value="upload">
    <div class="lbl">Загрузить файл конфига</div>
    <input type="file" id="f_file" name="upload_file" accept=".json,.bak">
    <div style="margin-top:12px">
      <div class="lbl">Сохранить как</div>
      <input type="text" id="f_savename" name="savename"
             placeholder="config-NAME.json.bak">
    </div>
    <div class="bak">Файл будет проверен через xray -test перед сохранением</div>
    <button type="submit">Загрузить и проверить</button>
  </form>
  <script>
  document.getElementById('f_file').addEventListener('change', function() {
    var n = this.files[0] ? this.files[0].name : '';
    if (n && !n.match(/\.bak$/)) n += '.bak';
    document.getElementById('f_savename').value = n;
  });
  </script>
</div>

<div class="card">
  <div class="lbl">Geo-файлы &nbsp;<code>%s</code></div>
  %s
  <div class="bak" style="margin-top:10px">Источник: geoip/geosite — Loyalsoldier, geosite-v2fly — v2fly dlc.<br>
  После скачивания: бэкап <code>.bak</code> → <code>xray -test</code> → рестарт xray. При ошибке — откат.</div>
</div>

<div class="card">
  <form method="POST">
    <input type="hidden" name="action" value="restore">
    <div class="lbl">Восстановить из бэкапа</div>
    <select name="restore_name" style="margin-top:8px">%s</select>
    <div class="bak">Бэкапы создаются автоматически перед каждой заменой · новейшие вверху</div>
    <button type="submit" style="background:#92400e">Восстановить</button>
  </form>
</div>

</body></html>]],
        CSS, active_badge, cur_html,
        toggle_html,
        message or '',
        opts,
        lists_html,
        bak_opts,
        html(gdir), geo_rows,
        restore_opts
    )
end

-- ── Main ──────────────────────────────────────────────────────────────────────

local method = os.getenv('REQUEST_METHOD') or 'GET'

if not check_auth() then
    local body = '<!DOCTYPE html><html><head><meta charset=UTF-8>'..
        '<style>body{font-family:monospace;max-width:380px;margin:120px auto;'..
        'background:#0f172a;color:#f87171;text-align:center}'..
        'p{color:#64748b}</style></head>'..
        '<body><h2>401 Unauthorized</h2><p>Введи логин и пароль</p></body></html>'
    io.write('Status: 401 Unauthorized\r\n')
    io.write('WWW-Authenticate: Basic realm="Xray Hop Updater"\r\n')
    io.write('Content-Type: text/html; charset=utf-8\r\n\r\n')
    io.write(body)
    return
end

if method == 'POST' then
    local ct  = os.getenv('CONTENT_TYPE') or ''
    local len = tonumber(os.getenv('CONTENT_LENGTH') or 0)
    local body = len > 0 and io.read(len) or ''

    local boundary = ct:match('boundary%s*=%s*"([^"]+)"')
                  or ct:match('boundary%s*=%s*([^;%s\r\n]+)')

    if boundary then
        -- multipart/form-data (загрузка файла)
        local parts  = parse_multipart(body, boundary)
        local action = (mp_field(parts, 'action') or ''):match('^%s*(.-)%s*$')

        if action == 'upload' then
            local file_part
            for _, p in ipairs(parts) do
                if p.name == 'upload_file' and p.filename then
                    file_part = p; break
                end
            end
            local savename = (mp_field(parts, 'savename') or ''):match('^%s*(.-)%s*$')

            local ok, result = pcall(function()
                if not file_part or file_part.content == '' then
                    error('Файл не выбран', 0)
                end
                if savename == '' then savename = file_part.filename end
                local valid, fname, out = upload_file(file_part.content, savename)
                if valid then
                    return string.format(
                        '<div class="msg ok">Загружен: <b>%s</b> · xray: OK</div>',
                        html(fname))
                else
                    local short = out:match('Main: (.+)') or out:sub(1, 300)
                    return string.format(
                        '<div class="msg err">Файл не прошёл валидацию xray · не сохранён:<br>'..
                        '<code>%s</code></div>',
                        html(short))
                end
            end)
            local msg = ok and result
                or string.format('<div class="msg err">Ошибка: %s</div>',
                   html(tostring(result)):gsub('\n', '<br>'))
            flash_save(msg)
            redirect_back()

        elseif action == 'hop' then
            local template   = (mp_field(parts, 'template')   or ''):match('^%s*(.-)%s*$')
            local vless_url  = (mp_field(parts, 'vless_url')  or ''):match('^%s*(.-)%s*$')
            local creds_json = (mp_field(parts, 'creds_json') or ''):match('^%s*(.-)%s*$')
            local file_part
            for _, p in ipairs(parts) do
                if p.name == 'creds_file' and p.filename and p.filename ~= '' then
                    file_part = p; break
                end
            end

            local ok, result = pcall(function()
                local ep, source
                if file_part and file_part.content:match('%S') then
                    ep = parse_creds_from_json(file_part.content)
                    source = 'файл ' .. (file_part.filename or '')
                elseif creds_json ~= '' then
                    ep = parse_creds_from_json(creds_json)
                    source = 'JSON-текст'
                elseif vless_url ~= '' then
                    ep = parse_vless(vless_url)
                    source = 'vless://'
                else
                    error('Укажи vless://, вставь JSON или выбери файл', 0)
                end
                local restarted, bak = apply(template, ep)
                local bak_info = bak ~= '' and (' · бэкап: <b>'..html(bak)..'</b>') or ''
                if restarted then
                    return string.format(
                        '<div class="msg ok">Готово: шаблон <b>%s</b> · entry-hop %s:%s | sni: %s · из %s%s</div>',
                        html(template), html(ep.host), ep.port, html(ep.sni), html(source), bak_info)
                else
                    return string.format(
                        '<div class="msg err">Конфиг записан%s, но xray не перезапустился</div>', bak_info)
                end
            end)
            local msg = ok and result
                or string.format('<div class="msg err">Ошибка: %s</div>',
                   html(tostring(result)):gsub('\n', '<br>'))
            flash_save(msg)
            redirect_back()

        else
            flash_save('<div class="msg err">Неизвестное действие</div>')
            redirect_back()
        end

    else
        -- application/x-www-form-urlencoded (все остальные формы)
        local data   = parse_qs(body)
        local action = (data.action or ''):match('^%s*(.-)%s*$')

        if action == 'restore' then
            local restore_name = (data.restore_name or ''):match('^%s*(.-)%s*$')
            local ok, result = pcall(function()
                local bak = restore_backup(restore_name)
                local bak_info = bak ~= '' and (' · текущий сохранён как <b>'..html(bak)..'</b>') or ''
                return string.format('<div class="msg ok">Восстановлен: <b>%s</b>%s</div>',
                    html(restore_name), bak_info)
            end)
            local msg = ok and result
                or string.format('<div class="msg err">Ошибка: %s</div>',
                   html(tostring(result)):gsub('\n', '<br>'))
            flash_save(msg)
            redirect_back()

        elseif action == 'toggle' then
            local st = (data.toggle_state or ''):match('^%s*(.-)%s*$')
            local ok, result = pcall(function()
                local out = proxy_toggle(st)
                local now_off  = proxy_disabled()
                local running  = xray_running()
                local label = (st == 'on') and 'Прокси включён' or 'Прокси выключен'
                return string.format(
                    '<div class="msg ok">%s · состояние: <b>%s</b> · процесс: %s<br><code>%s</code></div>',
                    label,
                    now_off and 'OFF' or 'ON',
                    running and 'running' or 'stopped',
                    html(out):gsub('\n', '<br>'))
            end)
            local msg = ok and result
                or string.format('<div class="msg err">Ошибка: %s</div>',
                   html(tostring(result)):gsub('\n', '<br>'))
            flash_save(msg)
            redirect_back()

        elseif action == 'rules' then
            local mode = (data.mode or 'merge'):match('^%s*(.-)%s*$')
            if mode ~= 'replace' then mode = 'merge' end
            local targets = {
                config    = (data.t_config    or '') ~= '',
                templates = (data.t_templates or '') ~= '',
            }
            local as_text = (data.format or '') == 'text'

            local ok, rep = pcall(function()
                -- list_foreign/list_ru; старые имена полей поддерживаем как алиасы
                local lists = {
                    foreign = parse_list(data.list_foreign or data.list_proxy),
                    ru      = parse_list(data.list_ru      or data.list_direct),
                }
                local seen = {}
                for _, d in ipairs(lists.foreign) do seen[d] = true end
                for _, d in ipairs(lists.ru) do
                    if seen[d] then
                        error('Домен и в заграничном, и в российском списке: ' .. d, 0)
                    end
                end
                -- «Заменить целиком» правит СУЩЕСТВУЮЩИЙ большой список конфига,
                -- поэтому частичный список стёр бы его. Требуем якорные домены.
                if mode == 'replace' then
                    for _, lane in ipairs(LANES) do
                        local set = {}
                        for _, d in ipairs(lists[lane]) do set[bare(d)] = true end
                        local hits = 0
                        for _, a in ipairs(ANCHORS[lane]) do if set[a] then hits = hits + 1 end end
                        if #lists[lane] > 0 and hits < ANCHOR_MIN then
                            error('Замена ' .. LANE_TITLE[lane] .. ' списка: прислан неполный список'
                                .. ' (нет опорных доменов). Для точечных правок используйте «добавить».', 0)
                        end
                    end
                end
                return apply_lists(lists, mode, targets)
            end)

            if as_text then
                io.write('Content-Type: text/plain; charset=utf-8\r\n\r\n')
                if not ok then
                    io.write('ERR: ' .. tostring(rep) .. '\n')
                else
                    io.write(string.format(
                        'OK mode=%s changed=%d nochange=%d added=%d moved=%d shadowed=%d nolist=%d broken=%d failed=%d\n',
                        mode, #rep.ok, #rep.nochange, rep.added, rep.moved, rep.shadowed,
                        #rep.nolist, #rep.broken, #rep.fail))
                    if #rep.ok > 0 then io.write('changed: ' .. table.concat(rep.ok, ' ') .. '\n') end
                    if #rep.nolist > 0 then
                        io.write('nolist (не опознаны списки, пропущены): '
                            .. table.concat(rep.nolist, ' ') .. '\n')
                    end
                    if #rep.broken > 0 then
                        io.write('broken (были невалидны и до правки, пропущены): '
                            .. table.concat(rep.broken, ' ') .. '\n')
                    end
                    for _, e in ipairs(rep.fail) do io.write('FAIL ' .. e .. '\n') end
                    if rep.restarted ~= nil then
                        io.write('xray: ' .. (rep.restarted == 'stopped' and 'был остановлен, не трогали'
                            or (rep.restarted and 'перезапущен' or 'ПЕРЕЗАПУСК НЕ УДАЛСЯ')) .. '\n')
                    end
                    io.write('backup: ' .. rep.bakdir .. '\n')
                end
            else
                local msg
                if not ok then
                    msg = string.format('<div class="msg err">Ошибка: %s</div>',
                        html(tostring(rep)):gsub('\n', '<br>'))
                else
                    local bits = { string.format(
                        'Списки сохранены (%s) · изменено файлов: <b>%d</b> · без изменений: %d · +%d доменов · перенесено из старых правил: %d',
                        mode == 'replace' and 'замена' or 'добавление',
                        #rep.ok, #rep.nochange, rep.added, rep.moved) }
                    if #rep.nolist > 0 then
                        bits[#bits+1] = 'Пропущены (нет опознаваемых списков): <b>'
                            .. html(table.concat(rep.nolist, ', ')) .. '</b>'
                    end
                    if rep.shadowed > 0 then
                        bits[#bits+1] = string.format(
                            '<b>Внимание:</b> %d домен(ов) перекрыты правилом выше — там маршрут решается раньше',
                            rep.shadowed)
                    end
                    if #rep.ok > 0 then
                        bits[#bits+1] = '<span class="bak">' .. html(table.concat(rep.ok, ', ')) .. '</span>'
                    end
                    if #rep.broken > 0 then
                        bits[#bits+1] = 'Пропущены (не проходят xray -test и без наших правок): <b>'
                            .. html(table.concat(rep.broken, ', ')) .. '</b>'
                    end
                    if rep.restarted == 'stopped' then
                        bits[#bits+1] = 'xray выключен — применится при следующем запуске'
                    elseif rep.restarted == false then
                        bits[#bits+1] = '<b>ВНИМАНИЕ: xray не перезапустился</b>'
                    elseif rep.restarted == true then
                        bits[#bits+1] = 'xray перезапущен'
                    end
                    bits[#bits+1] = '<span class="bak">бэкап: ' .. html(rep.bakdir) .. '</span>'
                    local cls = #rep.fail > 0 and 'err' or 'ok'
                    for _, e in ipairs(rep.fail) do
                        bits[#bits+1] = 'ОШИБКА ' .. html(e)
                    end
                    msg = '<div class="msg ' .. cls .. '">' .. table.concat(bits, '<br>') .. '</div>'
                end
                flash_save(msg)
                redirect_back()
            end

        elseif action == 'geo' then
            local key = (data.geo_file or ''):match('^%s*(.-)%s*$')
            local ok, result = pcall(function()
                local sz, status = update_geo(key)
                local g  = GEO[key] or { file = key }
                local mb = string.format('%.2f', sz / 1048576)
                local r
                if status == 'restarted' then
                    r = ' · xray перезапущен'
                elseif status == 'stopped' then
                    r = ' · xray выключен — применится при следующем запуске'
                else
                    r = ' · <b>ВНИМАНИЕ: xray не перезапустился</b>'
                end
                return string.format(
                    '<div class="msg ok">Обновлён <b>%s</b> (%s МБ) · xray -test OK%s</div>',
                    html(g.file), mb, r)
            end)
            local msg = ok and result
                or string.format('<div class="msg err">Ошибка: %s</div>',
                   html(tostring(result)):gsub('\n', '<br>'))
            flash_save(msg)
            redirect_back()

        elseif action == 'copy' then
            local bak_name = (data.bak_name or ''):match('^%s*(.-)%s*$')
            local ok, result = pcall(function()
                local bak = direct_copy(bak_name)
                local bak_info = bak ~= '' and (' · бэкап: <b>'..html(bak)..'</b>') or ''
                return string.format('<div class="msg ok">Применён: <b>%s</b>%s</div>',
                    html(bak_name), bak_info)
            end)
            local msg = ok and result
                or string.format('<div class="msg err">Ошибка: %s</div>',
                   html(tostring(result)):gsub('\n', '<br>'))
            flash_save(msg)
            redirect_back()

        else
            -- Entry-hop + шаблон
            local vless_url = (data.vless_url or ''):match('^%s*(.-)%s*$')
            local template  = (data.template  or ''):match('^%s*(.-)%s*$')
            local ok, result = pcall(function()
                local ep = parse_vless(vless_url)
                local restarted, bak = apply(template, ep)
                local bak_info = bak ~= '' and (' · бэкап: <b>'..html(bak)..'</b>') or ''
                if restarted then
                    return string.format(
                        '<div class="msg ok">Готово: шаблон <b>%s</b> · entry-hop %s:%s | sni: %s%s</div>',
                        html(template), html(ep.host), ep.port, html(ep.sni), bak_info)
                else
                    return string.format(
                        '<div class="msg err">Конфиг записан%s, но xray не перезапустился</div>', bak_info)
                end
            end)
            local msg = ok and result
                or string.format('<div class="msg err">Ошибка: %s</div>',
                   html(tostring(result)):gsub('\n', '<br>'))
            flash_save(msg)
            redirect_back()
        end
    end
else
    io.write(render(flash_read()))
end
