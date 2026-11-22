#!/usr/bin/env bash
#
# pxy-install.sh v4.3 — Xray + sing-box 多协议一键部署 (Debian/Ubuntu + systemd)
#
# 版本记录:
#   v1.0  8 个协议,随机参数,自签证书,第三方伪装域名
#   v2.0  新增自偷域名模式: Cloudflare DNS-01 自动签发/续签证书、伪装站点、nginx 回落
#   v3.0  vless-xhttp-enc / vless-ws-enc / vmess-ws 启用 TLS (ws 类仅声明 http/1.1)
#   v4.0  伪装站点由博客改为 API 接口站点 (JSON 接口 + openapi.json + /docs)
#   v4.1  随机端口范围改为 1000-5000 (自动避开跳跃区间 2300-3300)
#   v4.2  随机端口改为 3301-5000 (Hy2 跳跃区间固定 2300-3300);证书续签后同时重启 Xray;
#         自签模式链接改用 pcs= 证书指纹 (新版 Xray 系客户端已移除 allowInsecure);安装中断时给出提示
#   v4.3  本地证书检测与复用 (避免 Let's Encrypt 频率限制),进入续签窗口自动更新有效期,新增 renew-cert;
#         卸载默认保留证书;安装完成后自动执行一次时间同步
#
# Xray     : Vless-tcp-reality-vision / Vless-xhttp-reality-enc
#            Vless-xhttp-enc (TLS) / Vless-ws-enc (TLS) / Vmess-ws (TLS)
# sing-box : Tuic / AnyTLS / Hysteria2 (开启端口跳跃 2300:3300)
#
# 两种模式 (运行时交互选择):
#   自偷域名模式  填写已托管在 Cloudflare 的域名 + API Token 后:
#                 - 自动在 Cloudflare 创建/校正 A 记录 (仅 DNS,不走代理)
#                 - 本地已有该域名的有效证书时直接复用;否则 certbot 通过 DNS-01 申请 Let's Encrypt 证书
#                   并自动续签 (进入 30 天续签窗口时安装/renew-cert 会自动更新有效期)
#                 - 自动生成伪装 API 站点,nginx 仅监听 127.0.0.1 作为 Reality 的 target
#                 - Vless-reality-vision 监听 443,Tuic/AnyTLS/Hy2 使用正式证书
#   第三方伪装模式 域名留空: Reality 借用第三方大站,sing-box 使用自签证书
#
# UUID、密码、端口、路径、Reality 密钥与 shortId 全部随机生成。
#
# 用法:
#   bash pxy-install.sh             安装 (交互)
#   bash pxy-install.sh info        查看节点链接、服务和证书状态
#   bash pxy-install.sh upgrade     升级 Xray / sing-box 内核 (保留配置)
#   bash pxy-install.sh renew-cert  检查并更新本地证书有效期 (到期前 30 天内自动续签),并重载服务
#   bash pxy-install.sh uninstall   卸载 (默认保留该域名的证书,重装时自动复用)
#   --purge-cert                    卸载时同时删除该域名的证书
#   加 --no-service 只下载内核、生成并校验配置,不创建用户/服务/证书/防火墙规则
#
# 非交互 / 可选环境变量:
#   DOMAIN=xxx           自有域名 (留空则进入交互提问)
#   CF_TOKEN=xxx         Cloudflare API Token (权限: Zone-DNS-Edit + Zone-Zone-Read)
#   ACME_EMAIL=xxx       证书通知邮箱 (可空)
#   CF_MANAGE_DNS=1|0    是否由脚本创建/更新 A 记录 (默认 1)
#   ACME_STAGING=1       使用 Let's Encrypt 测试环境 (仅调试,证书不被信任)
#   CERT_FILE / KEY_FILE 使用已有的证书文件 (需同时指定;不会被本脚本自动续签)
#   FORCE_RENEW=1        强制续签 (会计入 Let's Encrypt 重复证书频率限制,谨慎使用)
#   SKIP_TIMESYNC=1      安装后不执行时间同步
#   SELF_STEAL_PORT=443  自偷模式下 Vision 节点端口 (默认 443)
#   PORT_MIN / PORT_MAX  随机端口范围 (默认 3301 / 5000;Hysteria2 跳跃区间固定为 UDP 2300-3300)
#   REALITY_SNI=xxx      第三方伪装模式下指定伪装域名
#   REALITY_PORT=443     第三方伪装模式下 Vision 节点固定端口 (默认随机)
#   VLESSENC_AUTH=mlkem  VLESS Encryption 使用 ML-KEM-768 (默认 X25519)
#   NODE_NAME=xxx        节点名前缀 (默认主机名)
#   SERVER_IP=x.x.x.x    手动指定公网 IP
#   CERT_SNI=xxx         自签证书的 CN/SNI (第三方伪装模式,默认 www.bing.com)

set -euo pipefail
umask 077

CONF_DIR="${PXY_DIR:-/etc/pxy}"
BIN_DIR="${PXY_BIN:-/usr/local/bin}"
SITE_DIR="${PXY_SITE:-/var/www/pxy-site}"
CF_API="${CF_API:-https://api.cloudflare.com/client/v4}"
VERSION="4.3"
SVC_USER="pxy"
HOP_START=2300
HOP_END=3300
NO_SERVICE=0
ASSUME_YES=0
CMD="install"
MODE="thirdparty"
NGINX_CONF="/etc/nginx/conf.d/pxy.conf"
HOOK_PATH="/usr/local/sbin/pxy-cert-deploy"
LE_DIR="${LE_DIR:-/etc/letsencrypt}"
CF_INI="$LE_DIR/cf-pxy.ini"
PURGE_CERT=0

log()  { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# ───────────────────────── 交互输入 ─────────────────────────

have_tty() { (exec </dev/tty) 2>/dev/null; }

ask() {   # ask 变量名 "提示" [默认值]   —— 变量已有值 (环境变量) 或无终端时不提问
  local __v="$1" __p="$2" __d="${3:-}" __a=""
  [ -z "${!__v:-}" ] || return 0
  have_tty || return 0
  read -r -p "$__p${__d:+ [$__d]}: " __a </dev/tty || true
  printf -v "$__v" '%s' "${__a:-$__d}"
}

ask_secret() {   # 输入不回显
  local __v="$1" __p="$2" __a=""
  [ -z "${!__v:-}" ] || return 0
  have_tty || return 0
  read -rs -p "$__p: " __a </dev/tty || true
  echo >/dev/tty
  printf -v "$__v" '%s' "$__a"
}

confirm() {   # confirm "提示" 默认(y|n)
  local def="${2:-n}" a=""
  if ! have_tty; then [ "$def" = y ]; return; fi
  read -r -p "$1 [$([ "$def" = y ] && echo Y/n || echo y/N)]: " a </dev/tty || true
  a="${a:-$def}"
  [[ "$a" =~ ^[Yy]$ ]]
}

collect_inputs() {
  MODE="thirdparty"
  ask DOMAIN "域名 (需已托管在 Cloudflare;留空 = 不使用自有域名)" ""
  DOMAIN="$(printf '%s' "${DOMAIN:-}" | tr '[:upper:]' '[:lower:]' | tr -d ' ')"
  [ -n "$DOMAIN" ] || return 0
  [[ "$DOMAIN" =~ ^([a-z0-9-]+\.)+[a-z0-9-]{2,}$ ]] || die "域名格式不正确: $DOMAIN"
  MODE="selfsteal"
  if [ "$NO_SERVICE" -eq 0 ]; then
    if have_tty && [ -z "${CF_TOKEN:-}" ]; then
      echo "  Cloudflare API Token 需要权限: Zone → DNS → Edit,以及 Zone → Zone → Read (限定到该域名所在区域即可)"
    fi
    ask_secret CF_TOKEN "Cloudflare API Token (输入不回显)"
    [ -n "${CF_TOKEN:-}" ] || die "未提供 Cloudflare API Token (可用 CF_TOKEN=xxx 传入)"
    ask ACME_EMAIL "证书通知邮箱 (可留空)" ""
    if [ -z "${CF_MANAGE_DNS:-}" ]; then
      if confirm "由脚本在 Cloudflare 自动创建/更新 $DOMAIN 的 A 记录 (指向本机,仅 DNS)?" y; then CF_MANAGE_DNS=1; else CF_MANAGE_DNS=0; fi
    fi
  fi
}

# ───────────────────────── 依赖与内核安装 ─────────────────────────

install_deps() {
  local pkgs=() c
  for c in curl unzip openssl jq; do command -v "$c" >/dev/null || pkgs+=("$c"); done
  if [ "$NO_SERVICE" -eq 0 ]; then
    command -v nft >/dev/null || pkgs+=(nftables)
    if [ "$MODE" = "selfsteal" ]; then
      command -v nginx >/dev/null || pkgs+=(nginx)
      command -v certbot >/dev/null || pkgs+=(certbot)
      dpkg -s python3-certbot-dns-cloudflare >/dev/null 2>&1 || pkgs+=(python3-certbot-dns-cloudflare)
    fi
  fi
  if [ "${#pkgs[@]}" -gt 0 ]; then
    command -v apt-get >/dev/null || die "缺少依赖 ${pkgs[*]},且不是 apt 系统,请手动安装"
    log "安装依赖: ${pkgs[*]}"
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${pkgs[@]}" ca-certificates
  fi
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  XRAY_ARCH=64;        SB_ARCH=amd64 ;;
    aarch64|arm64) XRAY_ARCH=arm64-v8a; SB_ARCH=arm64 ;;
    *) die "不支持的架构: $(uname -m)" ;;
  esac
}

latest_tag() {
  curl -fsSIL -o /dev/null -w '%{url_effective}' "https://github.com/$1/releases/latest" | sed 's#.*/tag/##'
}

install_xray() {
  local tag tmp
  tag=$(latest_tag XTLS/Xray-core)
  [ -n "$tag" ] || die "获取 Xray 版本失败,请检查服务器能否访问 github.com"
  log "安装 Xray $tag"
  tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/x.zip" "https://github.com/XTLS/Xray-core/releases/download/$tag/Xray-linux-$XRAY_ARCH.zip"
  unzip -qo "$tmp/x.zip" xray -d "$tmp"
  install -m 755 "$tmp/xray" "$BIN_DIR/xray"
  rm -rf "$tmp"
}

install_singbox() {
  local tag tmp
  tag=$(latest_tag SagerNet/sing-box)
  [ -n "$tag" ] || die "获取 sing-box 版本失败,请检查服务器能否访问 github.com"
  log "安装 sing-box $tag"
  tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/s.tgz" "https://github.com/SagerNet/sing-box/releases/download/$tag/sing-box-${tag#v}-linux-$SB_ARCH.tar.gz"
  tar -xzf "$tmp/s.tgz" -C "$tmp" --strip-components=1 --wildcards '*/sing-box'
  install -m 755 "$tmp/sing-box" "$BIN_DIR/sing-box"
  rm -rf "$tmp"
}

# ───────────────────────── 随机参数 ─────────────────────────

rand_uuid() { cat /proc/sys/kernel/random/uuid; }

rand_str() {   # rand_str 长度
  local s; s=$(openssl rand -base64 96 | tr -dc 'A-Za-z0-9')
  printf '%s' "${s:0:${1:-16}}"
}

pick_ports() {   # 从 PORT_MIN-PORT_MAX (默认 3301-5000) 中挑 9 个互不相同、未被占用的端口
  local p min="${PORT_MIN:-3301}" max="${PORT_MAX:-5000}"; PORTS=()
  while read -r p; do
    # 默认范围已在跳跃区间 (2300-3300) 之外;这里是自定义 PORT_MIN/PORT_MAX 时的保险
    if [ "$p" -ge "$HOP_START" ] && [ "$p" -le "$HOP_END" ]; then continue; fi
    if ss -lntuH 2>/dev/null | awk -v s=":$p\$" '$5 ~ s {f=1} END{exit !f}'; then continue; fi
    PORTS+=("$p")
    [ "${#PORTS[@]}" -eq 9 ] && break
  done < <(shuf -i "$min-$max" -n 600)
  [ "${#PORTS[@]}" -eq 9 ] || die "无法在 $min-$max 内挑选足够的空闲端口"
}

check_dest() {   # check_dest 主机 [端口] [SNI]  —— 目标必须支持 TLS1.3 + h2
  local h="$1" p="${2:-443}" s="${3:-$1}" out
  out=$(echo | timeout 8 openssl s_client -connect "$h:$p" -servername "$s" -tls1_3 -alpn h2 2>/dev/null || true)
  [[ "$out" == *"ALPN protocol: h2"* ]]
}

pick_reality_sni() {
  local c
  if [ -n "${REALITY_SNI:-}" ]; then
    SNI="$REALITY_SNI"
    check_dest "$SNI" || warn "$SNI 未通过 TLS1.3+h2 检测,Reality 可能无法正常工作"
    return
  fi
  for c in addons.mozilla.org www.samsung.com www.nvidia.com dl.google.com www.amazon.com; do
    if check_dest "$c"; then SNI="$c"; log "Reality 伪装域名: $SNI"; return; fi
  done
  die "候选伪装域名都未通过检测,请用 REALITY_SNI=xxx 指定一个支持 TLS1.3+h2 的站点"
}

gen_reality_keys() {
  local out
  out=$("$BIN_DIR/xray" x25519)
  R_PRIV=$(printf '%s\n' "$out" | awk -F': *' '/[Pp]rivate/ {print $2; exit}')
  R_PUB=$(printf '%s\n' "$out" | awk -F': *' '/[Pp]ublic|Password/ {print $2; exit}')
  [ -n "$R_PRIV" ] && [ -n "$R_PUB" ] || die "解析 xray x25519 输出失败"
}

gen_vlessenc() {   # 设置 DEC (服务端 decryption) / ENC (客户端 encryption)
  local out n=1
  [ "${VLESSENC_AUTH:-x25519}" = "mlkem" ] && n=2
  out=$("$BIN_DIR/xray" vlessenc)
  DEC=$(printf '%s\n' "$out" | grep '"decryption"' | sed -n "${n}p" | sed 's/.*": *"\(.*\)"$/\1/')
  ENC=$(printf '%s\n' "$out" | grep '"encryption"' | sed -n "${n}p" | sed 's/.*": *"\(.*\)"$/\1/')
  [ -n "$DEC" ] && [ -n "$ENC" ] || die "解析 xray vlessenc 输出失败 (需要较新的 Xray)"
}

resolve_ip() {   # 结果写入 PUBLIC_IP
  local ip u
  if [ -n "${PUBLIC_IP:-}" ]; then return 0; fi
  if [ -n "${SERVER_IP:-}" ]; then PUBLIC_IP="$SERVER_IP"; return 0; fi
  for u in https://api.ipify.org https://ip.sb https://ifconfig.me; do
    ip=$(curl -4fsS --max-time 5 "$u" 2>/dev/null || true)
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then PUBLIC_IP="$ip"; return 0; fi
  done
  die "获取公网 IP 失败,请用 SERVER_IP=x.x.x.x 指定"
}

gen_params() {
  pick_ports
  P_VISION=${PORTS[0]}; P_XHR=${PORTS[1]}; P_XH=${PORTS[2]}; P_WS=${PORTS[3]}
  P_VM=${PORTS[4]};     P_TUIC=${PORTS[5]}; P_ANYTLS=${PORTS[6]}; P_HY2=${PORTS[7]}
  P_NGX=${PORTS[8]}

  U_VISION=$(rand_uuid); U_XHR=$(rand_uuid); U_XH=$(rand_uuid); U_WS=$(rand_uuid)
  U_VM=$(rand_uuid);     U_TUIC=$(rand_uuid)
  PW_TUIC=$(rand_str 20); PW_ANYTLS=$(rand_str 20); PW_HY2=$(rand_str 20)

  PATH_XHR=$(rand_str 8); PATH_XH=$(rand_str 8); PATH_WS=$(rand_str 8); PATH_VM=$(rand_str 8)
  SID=$(openssl rand -hex 8)

  if [ "$MODE" = "selfsteal" ]; then
    SNI="$DOMAIN"
    TARGET="127.0.0.1:$P_NGX"
    P_VISION="${SELF_STEAL_PORT:-443}"
    CERT_SNI="$DOMAIN"
  else
    if [ -n "${REALITY_PORT:-}" ]; then P_VISION="$REALITY_PORT"; fi
    pick_reality_sni
    TARGET="$SNI:443"
    CERT_SNI="${CERT_SNI:-www.bing.com}"
  fi
  gen_reality_keys
  if [ -f /proc/net/if_inet6 ]; then LISTEN="::"; else LISTEN="0.0.0.0"; fi
}

gen_cert() {   # 自签 ECDSA 证书,有效期 10 年 (第三方伪装模式,或 --no-service 调试)
  openssl ecparam -genkey -name prime256v1 -noout -out "$CONF_DIR/cert.key"
  openssl req -new -x509 -days 3650 -key "$CONF_DIR/cert.key" -out "$CONF_DIR/cert.pem" \
    -subj "/CN=$CERT_SNI" -addext "subjectAltName=DNS:$CERT_SNI" 2>/dev/null
  CERT_FP=$(openssl x509 -in "$CONF_DIR/cert.pem" -noout -fingerprint -sha256 | cut -d= -f2)
}

# ───────────────────────── Cloudflare ─────────────────────────

cf() {   # cf 方法 路径 [JSON]  —— 成功时输出响应体;Token 通过 stdin 传给 curl,不出现在进程列表
  local m="$1" p="$2" d="${3:-}" out
  local args=(-sS -X "$m" "$CF_API$p" -H "Content-Type: application/json")
  [ -z "$d" ] || args+=(--data "$d")
  out=$(printf 'header = "Authorization: Bearer %s"\n' "$CF_TOKEN" | curl -K - "${args[@]}") \
    || { warn "无法连接 Cloudflare API"; return 1; }
  if [ "$(printf '%s' "$out" | jq -r '.success // false' 2>/dev/null)" != "true" ]; then
    warn "Cloudflare API 返回错误: $(printf '%s' "$out" | jq -r '[.errors[]?.message] | join("; ")' 2>/dev/null)"
    return 1
  fi
  printf '%s' "$out"
}

cf_find_zone() {   # 逐级去掉左侧子域名,找到 Token 可见的区域;设置 ZONE_ID / ZONE_NAME
  local name="$DOMAIN" out id
  while [[ "$name" == *.* ]]; do
    out=$(cf GET "/zones?name=$name") || return 1
    id=$(printf '%s' "$out" | jq -r '.result[0].id // empty')
    if [ -n "$id" ]; then ZONE_ID="$id"; ZONE_NAME="$name"; return 0; fi
    name="${name#*.}"
  done
  return 1
}

cf_check_dns() {   # cf_check_dns 本机IP
  local ip="$1" out id content proxied body n
  out=$(cf GET "/zones/$ZONE_ID/dns_records?type=A&name=$DOMAIN") || return 1
  id=$(printf '%s' "$out" | jq -r '.result[0].id // empty')
  content=$(printf '%s' "$out" | jq -r '.result[0].content // empty')
  proxied=$(printf '%s' "$out" | jq -r '.result[0].proxied // false')
  body=$(jq -nc --arg n "$DOMAIN" --arg c "$ip" '{type:"A",name:$n,content:$c,ttl:120,proxied:false}')

  if [ "${CF_MANAGE_DNS:-1}" = "1" ]; then
    if [ -z "$id" ]; then
      cf POST "/zones/$ZONE_ID/dns_records" "$body" >/dev/null || return 1
      log "已创建 A 记录: $DOMAIN → $ip (仅 DNS,未代理)"
    elif [ "$content" != "$ip" ]; then
      if confirm "A 记录当前指向 $content,是否改为本机 $ip?" y; then
        cf PUT "/zones/$ZONE_ID/dns_records/$id" "$body" >/dev/null || return 1
        log "已更新 A 记录: $DOMAIN → $ip (仅 DNS,未代理)"
      else
        warn "保留原 A 记录 ($content),Reality 自偷需要它指向本机 $ip"
      fi
    elif [ "$proxied" = "true" ]; then
      cf PUT "/zones/$ZONE_ID/dns_records/$id" "$body" >/dev/null || return 1
      log "已把 A 记录从\"代理(橙云)\"改为\"仅 DNS(灰云)\""
    else
      log "A 记录已正确: $DOMAIN → $ip (仅 DNS)"
    fi
  else
    if [ -z "$id" ]; then
      warn "Cloudflare 上没有 $DOMAIN 的 A 记录,请自行添加: A $DOMAIN → $ip,且必须是\"仅 DNS(灰云)\""
    elif [ "$content" != "$ip" ] || [ "$proxied" = "true" ]; then
      warn "A 记录需要指向 $ip 并关闭代理(灰云),当前: $content,代理=$proxied"
    fi
  fi

  n=$(cf GET "/zones/$ZONE_ID/dns_records?type=AAAA&name=$DOMAIN" | jq -r '.result | length' 2>/dev/null || echo 0)
  if [ "${n:-0}" -gt 0 ]; then
    warn "$DOMAIN 存在 AAAA 记录。请确认它指向本机 IPv6 且为灰云,否则请删除,以免探测流量走到别处"
  fi
}

cf_setup() {
  resolve_ip
  log "检查 Cloudflare 区域与 DNS 记录"
  cf_find_zone || die "该 Token 下找不到 $DOMAIN 所属的 Cloudflare 区域,请检查域名,以及 Token 权限 (Zone-Zone-Read / Zone-DNS-Edit)"
  log "Cloudflare 区域: $ZONE_NAME"
  cf_check_dns "$PUBLIC_IP" || die "Cloudflare DNS 操作失败"
}

# ───────────────────────── 证书 (certbot + DNS-01) ─────────────────────────

ensure_user() {
  id "$SVC_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
}

write_cf_credentials() {
  install -d -m 700 "$LE_DIR"
  printf 'dns_cloudflare_api_token = %s\n' "$CF_TOKEN" > "$CF_INI"
  chmod 600 "$CF_INI"
}

write_cert_hook() {   # 签发/续签成功后: 复制证书给 sing-box、Xray 和 nginx 使用,并重载服务
  cat > "$HOOK_PATH" <<EOF
#!/bin/sh
# 由 pxy-install.sh 生成: certbot 签发/续签成功后自动执行
set -e
[ -d "$CONF_DIR" ] || exit 0
getent group $SVC_USER >/dev/null 2>&1 || exit 0
L="\${RENEWED_LINEAGE:-$LE_DIR/live/$DOMAIN}"
install -m 640 -o root -g $SVC_USER "\$L/fullchain.pem" "$CONF_DIR/cert.pem"
install -m 640 -o root -g $SVC_USER "\$L/privkey.pem"   "$CONF_DIR/cert.key"
systemctl reload nginx >/dev/null 2>&1 || true
systemctl restart pxy-xray >/dev/null 2>&1 || true
systemctl restart pxy-singbox >/dev/null 2>&1 || true
EOF
  chmod 755 "$HOOK_PATH"
}

# ── 本地证书检测 ──

cert_days_left() {   # 剩余整天数 (已过期时为 0 或负数)
  local end
  end=$(date -d "$(openssl x509 -in "$1" -noout -enddate | cut -d= -f2)" +%s) || return 1
  echo $(( (end - $(date +%s)) / 86400 ))
}

key_matches() {   # 证书公钥与私钥是否配对
  [ "$(openssl x509 -in "$1" -noout -pubkey 2>/dev/null | sha256sum)" = "$(openssl pkey -in "$2" -pubout 2>/dev/null | sha256sum)" ]
}

cert_covers() {   # cert_covers 证书 域名  —— 精确匹配,或通配符 *.example.com 覆盖 a.example.com
  local names n d="$2"
  names=$(openssl x509 -in "$1" -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed -n 's/^ *DNS: *//p')
  [ -n "$names" ] || names=$(openssl x509 -in "$1" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *//p')
  while read -r n; do
    [ -n "$n" ] || continue
    if [ "$n" = "$d" ]; then return 0; fi
    if [[ "$n" == \*.* ]] && [[ "$d" == *.* ]] && [ "${d#*.}" = "${n#*.}" ]; then return 0; fi
  done <<<"$names"
  return 1
}

validate_local_cert() {   # validate_local_cert 证书 私钥 → 0 可用;1 不可用 (原因在 CERT_REASON: missing|mismatch|domain|staging|expired)
  local c="$1" k="$2" issuer
  CERT_REASON=""; CERT_DAYS=0; CERT_END=""
  if [ ! -s "$c" ] || [ ! -s "$k" ]; then CERT_REASON=missing; return 1; fi
  if ! key_matches "$c" "$k"; then CERT_REASON=mismatch; return 1; fi
  if ! cert_covers "$c" "$DOMAIN"; then CERT_REASON=domain; return 1; fi
  issuer=$(openssl x509 -in "$c" -noout -issuer 2>/dev/null || true)
  if [[ "$issuer" == *[Ss][Tt][Aa][Gg][Ii][Nn][Gg]* ]] && [ "${ACME_STAGING:-0}" != "1" ]; then CERT_REASON=staging; return 1; fi
  CERT_END=$(openssl x509 -in "$c" -noout -enddate | cut -d= -f2)
  CERT_DAYS=$(cert_days_left "$c")
  if ! openssl x509 -in "$c" -noout -checkend 0 >/dev/null 2>&1; then CERT_REASON=expired; return 1; fi
  return 0
}

cert_reason_text() {
  case "${CERT_REASON:-}" in
    missing)  echo "证书或私钥文件不存在/为空" ;;
    mismatch) echo "证书与私钥不匹配" ;;
    domain)   echo "证书不覆盖 $DOMAIN" ;;
    staging)  echo "这是 Let's Encrypt 测试环境 (STAGING) 证书,不被客户端信任" ;;
    expired)  echo "证书已过期" ;;
    *)        echo "未知原因" ;;
  esac
}

install_cert_files() {   # install_cert_files 证书 私钥
  install -m 640 -o root -g "$SVC_USER" "$1" "$CONF_DIR/cert.pem"
  install -m 640 -o root -g "$SVC_USER" "$2" "$CONF_DIR/cert.key"
}

reload_services() {
  systemctl reload nginx >/dev/null 2>&1 || true
  systemctl restart pxy-xray pxy-singbox >/dev/null 2>&1 || true
}

# ── certbot 证书的保留/恢复/清理 ──

restore_stashed_renewal() {   # 卸载时为避免定时任务空转,会把续签配置改名保存;重装时改回来
  local f="$LE_DIR/renewal/$DOMAIN.conf"
  if [ -f "$f.pxy-saved" ] && [ ! -f "$f" ]; then
    mv "$f.pxy-saved" "$f"
    log "已恢复 $DOMAIN 的证书续签配置"
  fi
}

purge_lineage() {   # 彻底删除该域名的 certbot 证书
  certbot delete --non-interactive --cert-name "$DOMAIN" >/dev/null 2>&1 || true
  rm -rf "$LE_DIR/live/$DOMAIN" "$LE_DIR/archive/$DOMAIN" "$LE_DIR/renewal/$DOMAIN.conf" "$LE_DIR/renewal/$DOMAIN.conf.pxy-saved"
}

renew_cert() {   # 只在进入续签窗口 (剩余 ≤30 天) 或已过期时才会真正向 Let's Encrypt 请求
  local args=(renew --cert-name "$DOMAIN" --non-interactive --deploy-hook "$HOOK_PATH")
  if [ "${FORCE_RENEW:-0}" = "1" ]; then args+=(--force-renewal); fi
  log "续签证书 (Cloudflare DNS-01)..."
  certbot "${args[@]}"
}

use_certbot_lineage() {   # 返回 0: 本地 certbot 证书已就位 (复用或续签);1: 没有可用证书,需要重新申请
  local live="$LE_DIR/live/$DOMAIN" c k
  c="$live/fullchain.pem"; k="$live/privkey.pem"
  [ -s "$c" ] && [ -s "$k" ] || return 1

  if validate_local_cert "$c" "$k"; then
    if [ "${FORCE_RENEW:-0}" = "1" ]; then
      warn "FORCE_RENEW=1: 强制续签 (计入 Let's Encrypt 重复证书频率限制)"
      renew_cert || return 1
    elif [ "$CERT_DAYS" -le 30 ]; then
      log "本地证书剩余 $CERT_DAYS 天 (到期 $CERT_END),已进入续签窗口,更新有效期"
      renew_cert || return 1
    else
      log "发现本地证书 (到期 $CERT_END,剩余 $CERT_DAYS 天),直接复用,不向 Let's Encrypt 申请"
    fi
  elif [ "$CERT_REASON" = "expired" ]; then
    log "本地证书已过期,尝试续签"
    renew_cert || return 1
  else
    warn "本地证书不可用: $(cert_reason_text);将删除并重新申请"
    purge_lineage
    return 1
  fi
  RENEWED_LINEAGE="$live" "$HOOK_PATH"
  CERT_SOURCE="certbot"
}

use_external_cert() {   # 使用 CERT_FILE / KEY_FILE 指定的证书
  validate_local_cert "$CERT_FILE" "$KEY_FILE" || die "指定的证书文件不可用: $(cert_reason_text)"
  install_cert_files "$CERT_FILE" "$KEY_FILE"
  CERT_SOURCE="external"
  log "使用指定的证书文件 (到期 $CERT_END,剩余 $CERT_DAYS 天)"
  if [ "$CERT_DAYS" -le 14 ]; then warn "该证书即将到期"; fi
  warn "外部证书不会被本脚本自动续签;更新证书文件后请运行: bash pxy-install.sh renew-cert"
}

issue_cert() {
  local args=(certonly --non-interactive --agree-tos --key-type ecdsa
              --dns-cloudflare --dns-cloudflare-credentials "$CF_INI"
              --dns-cloudflare-propagation-seconds 30
              --cert-name "$DOMAIN" -d "$DOMAIN" --deploy-hook "$HOOK_PATH")
  if [ -n "${ACME_EMAIL:-}" ]; then args+=(-m "$ACME_EMAIL" --no-eff-email); else args+=(--register-unsafely-without-email); fi
  if [ "${ACME_STAGING:-0}" = "1" ]; then args+=(--test-cert); warn "使用 Let's Encrypt 测试环境,签发的证书不被客户端信任"; fi

  log "本地没有可用证书,通过 Cloudflare DNS-01 申请 (约需 1 分钟)..."
  certbot "${args[@]}" || die "证书申请失败。常见原因: Token 权限不足、域名不在该 Token 的区域内、Let's Encrypt 频率限制 (同一域名每周最多 5 张重复证书)"
  RENEWED_LINEAGE="$LE_DIR/live/$DOMAIN" "$HOOK_PATH"
  [ -s "$CONF_DIR/cert.pem" ] && [ -s "$CONF_DIR/cert.key" ] || die "证书文件未就位"
  CERT_SOURCE="certbot"
  systemctl enable --now certbot.timer >/dev/null 2>&1 || true
  log "证书已签发,certbot.timer 负责自动续签 (到期前 30 天内续签)"
}

cert_summary() {
  if validate_local_cert "$CONF_DIR/cert.pem" "$CONF_DIR/cert.key"; then
    log "证书有效期至: $CERT_END (剩余 $CERT_DAYS 天)"
  else
    warn "当前证书状态异常: $(cert_reason_text)"
  fi
}

provision_cert() {   # 证书来源优先级: 指定文件 > 本地 certbot 证书 (复用/续签) > 重新申请
  restore_stashed_renewal
  write_cf_credentials
  write_cert_hook
  if [ -n "${CERT_FILE:-}" ] || [ -n "${KEY_FILE:-}" ]; then
    [ -n "${CERT_FILE:-}" ] && [ -n "${KEY_FILE:-}" ] || die "CERT_FILE 和 KEY_FILE 需要同时指定"
    use_external_cert
  elif ! use_certbot_lineage; then
    issue_cert
  fi
  systemctl enable --now certbot.timer >/dev/null 2>&1 || true
  cert_summary
}

# ───────────────────────── 伪装网站 + nginx ─────────────────────────

gen_site() {   # 生成 API 风格的伪装站点: openapi.json + /docs 文档页,其余接口由 nginx 直接返回 JSON
  local root="$SITE_DIR" i r label paths
  local pool=("users" "items" "orders" "projects" "invoices" "devices" "events" "reports")
  local regions=("ap-northeast-1" "ap-southeast-1" "us-west-2" "eu-central-1")

  label="${DOMAIN%%.*}"
  # api.example.com 这类域名: 首个标签太通用,改取下一级作站名
  if [[ "$label" =~ ^(api|www|app|rest|gateway|svc|service|backend|v[0-9]+)$ ]] && [[ "$DOMAIN" == *.*.* ]]; then
    label="${DOMAIN#*.}"; label="${label%%.*}"
  fi
  label="$(printf '%s' "${label:0:1}" | tr '[:lower:]' '[:upper:]')${label:1}"
  API_NAME="$label API"
  API_VER="1.$((RANDOM % 8 + 2)).$((RANDOM % 20))"
  API_REGION="${regions[RANDOM % ${#regions[@]}]}"
  API_RES=()
  while read -r i; do API_RES+=("${pool[$i]}"); done < <(shuf -i 0-7 -n 4)

  rm -rf "$root"
  mkdir -p "$root"

  paths=$(jq -nc '{
    "/health":    {"get":{"summary":"Health check","responses":{"200":{"description":"OK"}}}},
    "/v1/ping":   {"get":{"summary":"Connectivity check","responses":{"200":{"description":"OK"}}}},
    "/v1/time":   {"get":{"summary":"Server time","responses":{"200":{"description":"OK"}}}},
    "/v1/status": {"get":{"summary":"Service status","responses":{"200":{"description":"OK"}}}}
  }')
  for r in "${API_RES[@]}"; do
    paths=$(jq -c --arg p "/v1/$r" --arg n "$r" \
      '. + {($p): {"get": {"summary": ("List " + $n), "security": [{"bearerAuth": []}],
            "responses": {"200": {"description": "OK"}, "401": {"description": "Unauthorized"}}}}}' <<<"$paths")
  done
  jq -n --arg t "$API_NAME" --arg v "$API_VER" --argjson paths "$paths" \
    '{openapi:"3.0.3", info:{title:$t, version:$v, description:"REST API. Authenticate with a Bearer API key."},
      paths:$paths, components:{securitySchemes:{bearerAuth:{type:"http", scheme:"bearer"}}}}' > "$root/openapi.json"

  {
    cat <<EOF
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>$API_NAME Documentation</title>
<style>body{font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;max-width:760px;margin:40px auto;padding:0 20px;color:#1f2937}
code{background:#f3f4f6;padding:2px 6px;border-radius:4px}h1{margin-bottom:0}.v{color:#6b7280}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #e5e7eb;padding:8px;text-align:left}
@media (prefers-color-scheme:dark){body{background:#111827;color:#e5e7eb}code{background:#1f2937}td,th{border-color:#374151}}</style></head>
<body><h1>$API_NAME</h1><p class="v">Version $API_VER &middot; Region $API_REGION</p>
<p>Base URL: <code>https://$DOMAIN</code>. Send your API key as <code>Authorization: Bearer &lt;key&gt;</code>. The machine-readable spec is at <a href="/openapi.json">/openapi.json</a>.</p>
<table><tr><th>Method</th><th>Path</th><th>Auth</th></tr>
<tr><td>GET</td><td><code>/health</code></td><td>none</td></tr>
<tr><td>GET</td><td><code>/v1/ping</code></td><td>none</td></tr>
<tr><td>GET</td><td><code>/v1/time</code></td><td>none</td></tr>
<tr><td>GET</td><td><code>/v1/status</code></td><td>none</td></tr>
EOF
    for r in "${API_RES[@]}"; do
      printf '<tr><td>GET</td><td><code>/v1/%s</code></td><td>Bearer</td></tr>\n' "$r"
    done
    printf '</table></body></html>\n'
  } > "$root/docs.html"

  chmod -R a+rX "$root"
  log "伪装 API 站点已生成: $API_NAME v$API_VER (接口: health ping time status ${API_RES[*]})"
}

write_nginx() {
  local v6=""
  [ -f /proc/net/if_inet6 ] && v6="listen [::]:80 default_server;"
  cat > "$NGINX_CONF" <<EOF
# 由 pxy-install.sh 生成。HTTPS 端口只监听 127.0.0.1,仅作为 Xray Reality 的 target,不对公网开放。
server {
    listen 127.0.0.1:$P_NGX ssl http2 default_server;
    ssl_certificate     $CONF_DIR/cert.pem;
    ssl_certificate_key $CONF_DIR/cert.key;
    ssl_protocols TLSv1.3;
    return 444;
}

server {
    listen 127.0.0.1:$P_NGX ssl http2;
    server_name $DOMAIN;
    ssl_certificate     $CONF_DIR/cert.pem;
    ssl_certificate_key $CONF_DIR/cert.key;
    ssl_protocols TLSv1.3;
    server_tokens off;

    root $SITE_DIR;
    default_type application/json;
    limit_rate 512k;
    add_header Cache-Control "no-store" always;
    add_header X-Request-Id \$request_id always;
    add_header X-Content-Type-Options "nosniff" always;

    location = / { return 200 '{"name":"$API_NAME","version":"$API_VER","status":"ok","docs":"/docs","openapi":"/openapi.json"}'; }
    location = /health  { return 200 '{"status":"ok"}'; }
    location = /healthz { return 200 '{"status":"ok"}'; }
    location = /v1/ping { return 200 '{"pong":true}'; }
    location = /v1/time { return 200 '{"time":"\$time_iso8601","unix":\$msec}'; }
    location = /v1/status {
        return 200 '{"status":"operational","version":"$API_VER","region":"$API_REGION","time":"\$time_iso8601"}';
    }

    location = /openapi.json { try_files /openapi.json =404; }
    location = /docs { try_files /docs.html =404; }

    # 受保护资源: 没有密钥一律 401
    location ~ ^/v1/($(IFS='|'; echo "${API_RES[*]}"))(/|\$) {
        add_header Cache-Control "no-store" always;
        add_header X-Request-Id \$request_id always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header WWW-Authenticate 'Bearer realm="api"' always;
        return 401 '{"error":{"code":"unauthorized","message":"Missing or invalid API key."}}';
    }

    location / { return 404 '{"error":{"code":"not_found","message":"The requested resource was not found."}}'; }
}

server {
    listen 80 default_server;
    $v6
    server_name _;
    server_tokens off;
    return 301 https://$DOMAIN\$request_uri;
}
EOF
  chmod 644 "$NGINX_CONF"
}

# ───────────────────────── 配置文件 ─────────────────────────

write_xray() {
  # 三个非 Reality 入站 (vless-xhttp-enc / vless-ws-enc / vmess-ws) 统一启用 TLS
  # 自偷模式使用 Let's Encrypt 证书;第三方模式使用自签证书
  # 注意: WebSocket 只能协商 http/1.1,ALPN 带 h2 会导致 ws 连接失败,所以 ws 类入站只声明 http/1.1
  local cert='"certificates": [ { "certificateFile": "'"$CONF_DIR"'/cert.pem", "keyFile": "'"$CONF_DIR"'/cert.key" } ]'
  TLS_H2='"security": "tls",
        "tlsSettings": { "alpn": [ "h2", "http/1.1" ], '"$cert"' },'
  TLS_H1='"security": "tls",
        "tlsSettings": { "alpn": [ "http/1.1" ], '"$cert"' },'
  gen_vlessenc; D_XHR=$DEC; E_XHR=$ENC
  gen_vlessenc; D_XH=$DEC;  E_XH=$ENC
  gen_vlessenc; D_WS=$DEC;  E_WS=$ENC

  cat > "$CONF_DIR/xray.json" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "vless-reality-vision",
      "listen": "$LISTEN",
      "port": $P_VISION,
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "$U_VISION", "flow": "xtls-rprx-vision" } ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "dest": "$TARGET",
          "serverNames": [ "$SNI" ],
          "privateKey": "$R_PRIV",
          "shortIds": [ "$SID" ]
        }
      }
    },
    {
      "tag": "vless-xhttp-reality-enc",
      "listen": "$LISTEN",
      "port": $P_XHR,
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "$U_XHR" } ],
        "decryption": "$D_XHR"
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "reality",
        "xhttpSettings": { "path": "/$PATH_XHR", "mode": "auto" },
        "realitySettings": {
          "dest": "$TARGET",
          "serverNames": [ "$SNI" ],
          "privateKey": "$R_PRIV",
          "shortIds": [ "$SID" ]
        }
      }
    },
    {
      "tag": "vless-xhttp-enc",
      "listen": "$LISTEN",
      "port": $P_XH,
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "$U_XH" } ],
        "decryption": "$D_XH"
      },
      "streamSettings": {
        "network": "xhttp",
        $TLS_H2
        "xhttpSettings": { "path": "/$PATH_XH", "mode": "auto" }
      }
    },
    {
      "tag": "vless-ws-enc",
      "listen": "$LISTEN",
      "port": $P_WS,
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "$U_WS" } ],
        "decryption": "$D_WS"
      },
      "streamSettings": {
        "network": "ws",
        $TLS_H1
        "wsSettings": { "path": "/$PATH_WS" }
      }
    },
    {
      "tag": "vmess-ws",
      "listen": "$LISTEN",
      "port": $P_VM,
      "protocol": "vmess",
      "settings": { "clients": [ { "id": "$U_VM" } ] },
      "streamSettings": {
        "network": "ws",
        $TLS_H1
        "wsSettings": { "path": "/$PATH_VM" }
      }
    }
  ],
  "outbounds": [ { "protocol": "freedom", "tag": "direct" } ]
}
EOF
}

write_singbox() {
  cat > "$CONF_DIR/sing-box.json" <<EOF
{
  "log": { "level": "warn" },
  "inbounds": [
    {
      "type": "tuic",
      "tag": "tuic-in",
      "listen": "$LISTEN",
      "listen_port": $P_TUIC,
      "users": [ { "uuid": "$U_TUIC", "password": "$PW_TUIC" } ],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "alpn": [ "h3" ],
        "certificate_path": "$CONF_DIR/cert.pem",
        "key_path": "$CONF_DIR/cert.key"
      }
    },
    {
      "type": "anytls",
      "tag": "anytls-in",
      "listen": "$LISTEN",
      "listen_port": $P_ANYTLS,
      "users": [ { "password": "$PW_ANYTLS" } ],
      "tls": {
        "enabled": true,
        "certificate_path": "$CONF_DIR/cert.pem",
        "key_path": "$CONF_DIR/cert.key"
      }
    },
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "$LISTEN",
      "listen_port": $P_HY2,
      "users": [ { "password": "$PW_HY2" } ],
      "tls": {
        "enabled": true,
        "alpn": [ "h3" ],
        "certificate_path": "$CONF_DIR/cert.pem",
        "key_path": "$CONF_DIR/cert.key"
      }
    }
  ],
  "outbounds": [ { "type": "direct", "tag": "direct" } ]
}
EOF
}

write_hop() {   # Hysteria2 端口跳跃: UDP 2300-3300 重定向到 hy2 实际端口
  cat > "$CONF_DIR/hop.nft" <<EOF
table inet pxy_hop
delete table inet pxy_hop
table inet pxy_hop {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    udp dport $HOP_START-$HOP_END redirect to :$P_HY2
  }
}
EOF
  local tcp="$P_VISION $P_XHR $P_XH $P_WS $P_VM $P_ANYTLS"
  [ "$MODE" != "selfsteal" ] || tcp="$tcp 80"
  printf 'MODE="%s"\nDOMAIN="%s"\nCERT_SOURCE="%s"\nCERT_FILE="%s"\nKEY_FILE="%s"\nTCP_PORTS="%s"\nUDP_PORTS="%s"\n' \
    "$MODE" "${DOMAIN:-}" "${CERT_SOURCE:-}" "${CERT_FILE:-}" "${KEY_FILE:-}" "$tcp" "$P_TUIC $P_HY2" > "$CONF_DIR/ports.env"
}

validate() {
  log "校验配置"
  "$BIN_DIR/xray" run -test -c "$CONF_DIR/xray.json" >/dev/null || die "Xray 配置校验失败"
  "$BIN_DIR/sing-box" check -c "$CONF_DIR/sing-box.json" || die "sing-box 配置校验失败"
  if [ "$NO_SERVICE" -eq 0 ]; then nft -c -f "$CONF_DIR/hop.nft" || die "nftables 规则校验失败"; fi
}

# ───────────────────────── 系统集成 ─────────────────────────

preflight() {
  if [ "$MODE" = "selfsteal" ] && ss -lntH 2>/dev/null | awk -v s=":$P_VISION\$" '$4 ~ s {f=1} END{exit !f}'; then
    die "TCP $P_VISION 已被占用 (自偷模式需要 Xray 监听它),请先停掉占用进程,或用 SELF_STEAL_PORT 指定其他端口"
  fi
  if [ "$MODE" = "selfsteal" ] && ss -lntH 2>/dev/null | awk '$4 ~ /:80$/ {f=1} END{exit !f}'; then
    if ! systemctl is-active --quiet nginx 2>/dev/null; then
      die "TCP 80 已被其他程序占用 (nginx 需要它做 HTTP 跳转),请先处理"
    fi
  fi
}

setup_nginx() {
  rm -f /etc/nginx/sites-enabled/default
  nginx -t >/dev/null 2>&1 || { nginx -t; rm -f "$NGINX_CONF"; die "nginx 配置校验失败"; }
  systemctl enable nginx >/dev/null 2>&1 || true
  systemctl restart nginx
  sleep 1
  check_dest 127.0.0.1 "$P_NGX" "$DOMAIN" \
    || die "伪装站点 (127.0.0.1:$P_NGX) 未通过 TLS1.3+h2 检测,请查看: journalctl -u nginx -n 30"
  log "伪装站点就绪: https://$DOMAIN (经 Reality 回落,通过 TLS1.3+h2 检测)"
}

setup_system() {
  ensure_user
  chown -R "root:$SVC_USER" "$CONF_DIR"
  chmod 750 "$CONF_DIR"
  chmod 640 "$CONF_DIR/xray.json" "$CONF_DIR/sing-box.json" "$CONF_DIR/cert.pem" "$CONF_DIR/cert.key"

  cat > /etc/sysctl.d/99-pxy.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=16777216
net.core.wmem_max=16777216
EOF
  sysctl -p /etc/sysctl.d/99-pxy.conf >/dev/null 2>&1 || warn "sysctl 部分参数未生效 (不影响使用)"

  cat > /etc/systemd/system/pxy-xray.service <<EOF
[Unit]
Description=Xray (pxy)
After=network-online.target nginx.service
Wants=network-online.target

[Service]
User=$SVC_USER
ExecStart=$BIN_DIR/xray run -c $CONF_DIR/xray.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/pxy-singbox.service <<EOF
[Unit]
Description=sing-box (pxy)
After=network-online.target pxy-hop.service
Wants=network-online.target

[Service]
User=$SVC_USER
ExecStart=$BIN_DIR/sing-box run -c $CONF_DIR/sing-box.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/pxy-hop.service <<EOF
[Unit]
Description=pxy Hysteria2 port hopping
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$(command -v nft) -f $CONF_DIR/hop.nft
ExecStop=$(command -v nft) delete table inet pxy_hop

[Install]
WantedBy=multi-user.target
EOF

  open_firewall
  systemctl daemon-reload
  [ "$MODE" != "selfsteal" ] || setup_nginx
  systemctl enable --now pxy-hop pxy-xray pxy-singbox >/dev/null 2>&1
  sleep 2
  local s
  for s in pxy-hop pxy-xray pxy-singbox; do
    if ! systemctl is-active --quiet "$s"; then
      journalctl -u "$s" -n 20 --no-pager || true
      die "$s 启动失败"
    fi
  done
}

open_firewall() {   # 仅当 ufw 已启用时放行端口
  local st p
  command -v ufw >/dev/null || return 0
  st=$(ufw status 2>/dev/null || true)
  [[ "$st" == *"Status: active"* ]] || return 0
  # shellcheck disable=SC1091
  . "$CONF_DIR/ports.env"
  log "ufw 已启用,放行端口"
  for p in $TCP_PORTS; do ufw allow "$p/tcp" >/dev/null; done
  for p in $UDP_PORTS; do ufw allow "$p/udp" >/dev/null; done
  ufw allow "$HOP_START:$HOP_END/udp" >/dev/null
}

# ───────────────────────── 时间同步 ─────────────────────────

sync_time() {   # 安装完成后自动执行一次: vmess 要求客户端与服务器时间误差 < 2 分钟,证书校验也依赖正确的系统时间
  [ "${SKIP_TIMESYNC:-0}" != "1" ] || return 0
  log "同步系统时间"
  local i st t method=""
  if command -v chronyc >/dev/null 2>&1 && { systemctl is-active --quiet chrony || systemctl is-active --quiet chronyd; } 2>/dev/null; then
    method="chrony"
    chronyc -a makestep >/dev/null 2>&1 || chronyc makestep >/dev/null 2>&1 || true
  elif systemctl cat systemd-timesyncd >/dev/null 2>&1; then
    method="systemd-timesyncd"
    systemctl enable --now systemd-timesyncd >/dev/null 2>&1 || true
    timedatectl set-ntp true >/dev/null 2>&1 || true
    systemctl restart systemd-timesyncd >/dev/null 2>&1 || true
  elif command -v apt-get >/dev/null 2>&1; then
    method="chrony (新安装)"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq chrony >/dev/null 2>&1 \
      || { warn "chrony 安装失败,已跳过时间同步"; return 0; }
    systemctl enable --now chrony >/dev/null 2>&1 || true
    sleep 2
    chronyc -a makestep >/dev/null 2>&1 || true
  else
    warn "未找到时间同步服务,已跳过"
    return 0
  fi

  for i in $(seq 1 "${TIMESYNC_WAIT:-10}"); do
    st=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)
    t=$(chronyc tracking 2>/dev/null || true)
    if [ "$st" = "yes" ] || [[ "$t" =~ Leap\ status[[:space:]]*:\ Normal ]]; then
      log "时间已同步 ($method): $(date '+%F %T %Z')"
      return 0
    fi
    sleep 2
  done
  warn "时间同步尚未确认 ($method)。稍后可检查: timedatectl 或 chronyc tracking (OpenVZ 等虚拟化不允许修改系统时间)"
}

# ───────────────────────── 节点链接 ─────────────────────────

render_nodes() {
  local n ip vm sb_note ins_tuic="" ins_any="" ins_hy="" pin_hy="" ins_tls=""
  n="${NODE_NAME:-$(hostname -s)}"
  resolve_ip; ip="$PUBLIC_IP"
  vm=$(printf '{"v":"2","ps":"%s-vmess-ws","add":"%s","port":"%s","id":"%s","aid":"0","scy":"auto","net":"ws","type":"none","host":"%s","path":"/%s","tls":"tls","sni":"%s","alpn":"http/1.1"}' \
        "$n" "$ip" "$P_VM" "$U_VM" "$CERT_SNI" "$PATH_VM" "$CERT_SNI" | base64 -w0)

  if [ "$MODE" = "selfsteal" ]; then
    sb_note="# ── sing-box (正式证书 $DOMAIN,自动续签;地址用 IP,SNI 用域名) ──"
  else
    sb_note="# ── sing-box (自签证书: 客户端需开启\"允许不安全/跳过证书验证\",或使用指纹固定) ──"
    # 说明: Xray 系链接 (xhttp-enc / ws-enc) 已用 pcs= 固定证书指纹;vmess-ws 链接无此字段,需在客户端手动固定指纹或开启允许不安全
    ins_tuic="&allow_insecure=1"; ins_any="&insecure=1"; ins_hy="&insecure=1"; pin_hy="&pinSHA256=$CERT_FP"
    ins_tls="&pcs=$(printf '%s' "$CERT_FP" | tr -d ':' | tr 'A-F' 'a-f')"
  fi

  cat > "$CONF_DIR/nodes.txt" <<EOF
# ── Xray ($MODE 模式,Reality SNI: $SNI) ──
vless://$U_VISION@$ip:$P_VISION?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$SNI&fp=chrome&pbk=$R_PUB&sid=$SID&type=tcp&headerType=none#$n-vless-reality-vision

vless://$U_XHR@$ip:$P_XHR?encryption=$E_XHR&security=reality&sni=$SNI&fp=chrome&pbk=$R_PUB&sid=$SID&type=xhttp&path=%2F$PATH_XHR&mode=auto#$n-vless-xhttp-reality-enc

vless://$U_XH@$ip:$P_XH?encryption=$E_XH&security=tls&sni=$CERT_SNI&alpn=h2%2Chttp%2F1.1&type=xhttp&path=%2F$PATH_XH&mode=auto$ins_tls#$n-vless-xhttp-enc

vless://$U_WS@$ip:$P_WS?encryption=$E_WS&security=tls&sni=$CERT_SNI&alpn=http%2F1.1&type=ws&path=%2F$PATH_WS$ins_tls#$n-vless-ws-enc

vmess://$vm

$sb_note
tuic://$U_TUIC:$PW_TUIC@$ip:$P_TUIC?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=$CERT_SNI$ins_tuic#$n-tuic

anytls://$PW_ANYTLS@$ip:$P_ANYTLS?sni=$CERT_SNI$ins_any#$n-anytls

hysteria2://$PW_HY2@$ip:$P_HY2?sni=$CERT_SNI$ins_hy&alpn=h3&mport=$HOP_START-$HOP_END$pin_hy#$n-hysteria2
EOF
  if [ "$MODE" != "selfsteal" ]; then
    printf '\n# 自签证书 SHA256 指纹 (可用于固定证书): %s\n' "$CERT_FP" >> "$CONF_DIR/nodes.txt"
  fi
}

# ───────────────────────── 子命令 ─────────────────────────

do_install() {
  [ ! -f "$CONF_DIR/xray.json" ] || die "已安装。查看节点: pxy-install.sh info;重装请先 uninstall"
  INSTALL_OK=0
  trap '[ "$INSTALL_OK" = 1 ] || warn "安装未完成。排查原因后,请先执行 uninstall 清理,再重新安装"' EXIT
  collect_inputs
  install_deps
  detect_arch
  mkdir -p "$BIN_DIR" "$CONF_DIR"
  install_xray
  install_singbox
  gen_params

  if [ "$MODE" = "selfsteal" ] && [ "$NO_SERVICE" -eq 0 ]; then
    preflight
    ensure_user
    cf_setup
    provision_cert
  else
    gen_cert
  fi

  write_xray
  write_singbox
  write_hop
  validate
  if [ "$MODE" = "selfsteal" ]; then
    gen_site
    write_nginx
  fi
  render_nodes
  [ "$NO_SERVICE" -eq 1 ] || setup_system
  [ "$NO_SERVICE" -eq 1 ] || sync_time
  INSTALL_OK=1

  echo
  log "完成。节点链接 (同时保存在 $CONF_DIR/nodes.txt):"
  echo
  cat "$CONF_DIR/nodes.txt"
  echo
  cat <<EOF
注意:
  1. 云厂商面板如果有安全组/防火墙,需放行上面所有 TCP/UDP 端口,以及 UDP $HOP_START-$HOP_END$([ "$MODE" = selfsteal ] && echo ",TCP 80")。
  2. 查看日志: journalctl -u pxy-xray -f    journalctl -u pxy-singbox -f
  2b. 第三方模式下 TLS 节点使用自签证书: Xray 系链接已带 pcs= 证书指纹;vmess-ws 需在客户端手动固定指纹或开启"允许不安全"
  3. 再次查看节点: bash pxy-install.sh info
EOF
  if [ "$MODE" = "selfsteal" ]; then
    cat <<EOF
  4. 伪装 API 站点: https://$DOMAIN  (浏览器打开返回 JSON;/docs 是接口文档,/openapi.json 是接口描述)
  5. 证书自动续签由 certbot.timer 负责 (certbot renew --dry-run 可验证续签流程);随时检查并更新有效期: bash pxy-install.sh renew-cert。
     卸载默认保留证书,重装时会直接复用,避免触发 Let's Encrypt 频率限制;要一并删除请加 --purge-cert。
  6. Cloudflare 上 $DOMAIN 的 A 记录必须保持"仅 DNS (灰云)",开启代理 (橙云) 会让 Reality 失效,并可能被他人当作转发节点。
EOF
  fi
}

do_info() {
  [ -f "$CONF_DIR/nodes.txt" ] || die "未安装"
  local s unit
  for s in pxy-hop pxy-xray pxy-singbox nginx; do
    if [ "$s" = nginx ] && ! grep -q '^MODE="selfsteal"' "$CONF_DIR/ports.env" 2>/dev/null; then continue; fi
    printf '%-14s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || true)"
  done
  if [ -s "$CONF_DIR/cert.pem" ]; then
    printf '%-14s %s\n' "证书到期" "$(openssl x509 -in "$CONF_DIR/cert.pem" -noout -enddate | cut -d= -f2)"
  fi
  printf '%-14s %s\n' "时间同步" "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unknown)"
  unit=$(systemctl is-active certbot.timer 2>/dev/null || true)
  [ "$unit" = "active" ] && printf '%-14s %s\n' "certbot.timer" "$unit"
  echo
  cat "$CONF_DIR/nodes.txt"
}

do_upgrade() {
  [ -f "$CONF_DIR/xray.json" ] || die "未安装"
  install_deps
  detect_arch
  install_xray
  install_singbox
  validate
  if [ "$NO_SERVICE" -eq 0 ]; then systemctl restart pxy-xray pxy-singbox; fi
  log "升级完成"
}

do_renew_cert() {   # 检查并更新本地证书有效期
  [ -f "$CONF_DIR/ports.env" ] || die "未安装"
  local MODE="" DOMAIN="" CERT_SOURCE="" CERT_FILE="" KEY_FILE=""
  # shellcheck disable=SC1091
  . "$CONF_DIR/ports.env"
  [ "$MODE" = "selfsteal" ] || die "仅自偷域名模式使用正式证书,无需续签"
  write_cert_hook
  if [ "$CERT_SOURCE" = "external" ]; then
    use_external_cert
    reload_services
  else
    use_certbot_lineage || die "本地没有可用证书,或续签失败。请检查 Cloudflare Token / 网络,或重新安装"
  fi
  cert_summary
}

do_uninstall() {
  [ -d "$CONF_DIR" ] || die "未安装"
  if [ "$ASSUME_YES" -eq 0 ]; then
    read -rp "确认卸载 (将删除所有配置、节点信息和伪装 API 站点)? [y/N] " ans </dev/tty || ans=n
    [[ "$ans" =~ ^[Yy]$ ]] || exit 0
  fi
  local p TCP_PORTS="" UDP_PORTS="" MODE="" DOMAIN=""
  # shellcheck disable=SC1091
  [ -f "$CONF_DIR/ports.env" ] && . "$CONF_DIR/ports.env"
  systemctl disable --now pxy-singbox pxy-xray pxy-hop >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/pxy-{xray,singbox,hop}.service /etc/sysctl.d/99-pxy.conf
  systemctl daemon-reload
  nft delete table inet pxy_hop >/dev/null 2>&1 || true
  if command -v ufw >/dev/null; then
    for p in $TCP_PORTS; do ufw delete allow "$p/tcp" >/dev/null 2>&1 || true; done
    for p in $UDP_PORTS; do ufw delete allow "$p/udp" >/dev/null 2>&1 || true; done
    ufw delete allow "$HOP_START:$HOP_END/udp" >/dev/null 2>&1 || true
  fi
  if [ "$MODE" = "selfsteal" ]; then
    rm -f "$NGINX_CONF" "$HOOK_PATH" "$CF_INI"
    rm -rf "$SITE_DIR"
    systemctl reload nginx >/dev/null 2>&1 || true
    if [ -n "$DOMAIN" ]; then
      if [ "$PURGE_CERT" -eq 0 ] && [ "$ASSUME_YES" -eq 0 ] && have_tty; then
        if confirm "同时删除 $DOMAIN 的 Let's Encrypt 证书? (保留可在重装时直接复用,避免触发频率限制)" n; then PURGE_CERT=1; fi
      fi
      if [ "$PURGE_CERT" -eq 1 ]; then
        purge_lineage
        log "已删除 $DOMAIN 的证书"
      elif [ -f "$LE_DIR/renewal/$DOMAIN.conf" ]; then
        mv "$LE_DIR/renewal/$DOMAIN.conf" "$LE_DIR/renewal/$DOMAIN.conf.pxy-saved"
        log "已保留 $DOMAIN 的证书,重装时自动复用;已停用其自动续签,并删除保存的 Cloudflare Token"
      fi
    fi
    warn "未删除 nginx/certbot 软件包,也未改动 Cloudflare 上的 DNS 记录"
  fi
  rm -rf "$CONF_DIR"
  rm -f "$BIN_DIR/xray" "$BIN_DIR/sing-box"
  id "$SVC_USER" >/dev/null 2>&1 && userdel "$SVC_USER" || true
  log "已卸载"
}

main() {
  local a
  for a in "$@"; do
    case "$a" in
      --no-service) NO_SERVICE=1 ;;
      -y|--yes) ASSUME_YES=1 ;;
      --purge-cert) PURGE_CERT=1 ;;
      -v|--version) echo "pxy-install.sh v$VERSION"; exit 0 ;;
      install|info|upgrade|uninstall|renew-cert) CMD="$a" ;;
      *) die "未知参数: $a" ;;
    esac
  done
  [ "$(id -u)" -eq 0 ] || die "请使用 root 运行"
  log "pxy-install.sh v$VERSION"
  if [ "$NO_SERVICE" -eq 1 ]; then NGINX_CONF="$CONF_DIR/nginx-pxy.conf"; fi

  case "$CMD" in
    install)   do_install ;;
    info)      do_info ;;
    upgrade)   do_upgrade ;;
    uninstall) do_uninstall ;;
    renew-cert) do_renew_cert ;;
  esac
}

# 被 source 时 (测试) 不自动执行
if [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; fi
