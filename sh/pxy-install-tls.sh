#!/usr/bin/env bash
#
# pxy-install.sh — Xray + sing-box 多协议一键部署 (Debian/Ubuntu + systemd)
#
# Xray     : Vless-tcp-reality-vision / Vless-xhttp-reality-enc / Vless-xhttp-tls-enc
#            Vless-ws-tls-enc / Vmess-ws-tls
# sing-box : Tuic / AnyTLS / Hysteria2 (开启端口跳跃 2300:3300)
#
# 两种模式 (运行时交互选择):
#   自偷域名模式  填写已托管在 Cloudflare 的域名 + API Token 后:
#                 - 自动在 Cloudflare 创建/校正 A 记录 (仅 DNS,不走代理)
#                 - certbot 通过 DNS-01 申请 Let's Encrypt 证书并自动续签
#                 - 自动生成伪装网站,nginx 仅监听 127.0.0.1 作为 Reality 的 target
#                 - Vless-reality-vision 监听 443,Tuic/AnyTLS/Hy2 使用正式证书
#   第三方伪装模式 域名留空: Reality 借用第三方大站,sing-box 使用自签证书
#
# UUID、密码、端口、路径、Reality 密钥与 shortId 全部随机生成。
#
# 用法:
#   bash pxy-install.sh             安装 (交互)
#   bash pxy-install.sh info        查看节点链接、服务和证书状态
#   bash pxy-install.sh upgrade     升级 Xray / sing-box 内核 (保留配置)
#   bash pxy-install.sh uninstall   卸载
#   加 --no-service 只下载内核、生成并校验配置,不创建用户/服务/证书/防火墙规则
#
# 非交互 / 可选环境变量:
#   DOMAIN=xxx           自有域名 (留空则进入交互提问)
#   CF_TOKEN=xxx         Cloudflare API Token (权限: Zone-DNS-Edit + Zone-Zone-Read)
#   ACME_EMAIL=xxx       证书通知邮箱 (可空)
#   CF_MANAGE_DNS=1|0    是否由脚本创建/更新 A 记录 (默认 1)
#   ACME_STAGING=1       使用 Let's Encrypt 测试环境 (仅调试,证书不被信任)
#   SELF_STEAL_PORT=443  自偷模式下 Vision 节点端口 (默认 443)
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
SVC_USER="pxy"
HOP_START=2300
HOP_END=3300
NO_SERVICE=0
ASSUME_YES=0
CMD="install"
MODE="thirdparty"
NGINX_CONF="/etc/nginx/conf.d/pxy.conf"
HOOK_PATH="/usr/local/sbin/pxy-cert-deploy"
CF_INI="/etc/letsencrypt/cf-pxy.ini"

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

pick_ports() {   # 从 10000-65000 中挑 9 个互不相同且未被占用的端口 (与跳跃区间 2300-3300 不重叠)
  local p; PORTS=()
  while read -r p; do
    if ss -lntuH 2>/dev/null | awk -v s=":$p\$" '$5 ~ s {f=1} END{exit !f}'; then continue; fi
    PORTS+=("$p")
    [ "${#PORTS[@]}" -eq 9 ] && break
  done < <(shuf -i 10000-65000 -n 64)
  [ "${#PORTS[@]}" -eq 9 ] || die "无法挑选足够的空闲端口"
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

write_cert_hook() {   # 签发/续签成功后: 复制证书给 sing-box 和 nginx 使用,并重载服务
  cat > "$HOOK_PATH" <<EOF
#!/bin/sh
# 由 pxy-install.sh 生成: certbot 签发/续签成功后自动执行
set -e
L="\${RENEWED_LINEAGE:-/etc/letsencrypt/live/$DOMAIN}"
install -m 640 -o root -g $SVC_USER "\$L/fullchain.pem" "$CONF_DIR/cert.pem"
install -m 640 -o root -g $SVC_USER "\$L/privkey.pem"   "$CONF_DIR/cert.key"
systemctl reload nginx >/dev/null 2>&1 || true
systemctl restart pxy-xray pxy-singbox >/dev/null 2>&1 || true
EOF
  chmod 755 "$HOOK_PATH"
}

issue_cert() {
  install -d -m 700 /etc/letsencrypt
  printf 'dns_cloudflare_api_token = %s\n' "$CF_TOKEN" > "$CF_INI"
  chmod 600 "$CF_INI"
  write_cert_hook

  local args=(certonly --non-interactive --agree-tos --key-type ecdsa
              --dns-cloudflare --dns-cloudflare-credentials "$CF_INI"
              --dns-cloudflare-propagation-seconds 30
              --cert-name "$DOMAIN" -d "$DOMAIN" --deploy-hook "$HOOK_PATH")
  if [ -n "${ACME_EMAIL:-}" ]; then args+=(-m "$ACME_EMAIL" --no-eff-email); else args+=(--register-unsafely-without-email); fi
  if [ "${ACME_STAGING:-0}" = "1" ]; then args+=(--test-cert); warn "使用 Let's Encrypt 测试环境,签发的证书不被客户端信任"; fi

  log "通过 Cloudflare DNS-01 申请证书 (约需 1 分钟)..."
  certbot "${args[@]}" || die "证书申请失败。常见原因: Token 权限不足、域名不在该 Token 的区域内、Let's Encrypt 频率限制"
  RENEWED_LINEAGE="/etc/letsencrypt/live/$DOMAIN" "$HOOK_PATH"
  [ -s "$CONF_DIR/cert.pem" ] && [ -s "$CONF_DIR/cert.key" ] || die "证书文件未就位"
  systemctl enable --now certbot.timer >/dev/null 2>&1 || true
  log "证书已签发,certbot.timer 负责自动续签 (到期前 30 天内续签)"
}

# ───────────────────────── 伪装网站 + nginx ─────────────────────────

html_page() {   # html_page 标题 正文HTML   (依赖 gen_site 中的 name / yr 变量)
  cat <<EOF
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>$1 · $name</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="stylesheet" href="/style.css"></head>
<body><header><a class="brand" href="/">$name</a><nav><a href="/">Notes</a><a href="/about.html">About</a></nav></header>
<main>
$2
</main>
<footer>&copy; $yr $name</footer></body></html>
EOF
}

gen_site() {   # 生成一个体积很小 (几十 KB) 的静态博客,内容、配色、日期随机
  local root="$SITE_DIR" name accent yr i n d list=""
  local accents=("#2563eb" "#0f766e" "#b45309" "#7c3aed" "#be123c" "#15803d")
  local titles=(
    "Keeping a small VPS healthy"
    "Why I still write plain HTML"
    "A weekend with SQLite"
    "Backups you will actually restore"
    "Reading logs without losing your mind"
    "Small habits for calmer deployments")
  local p1=(
    "A small server does not need much attention, but it does need some. I check disk usage, pending updates and failed services once a week, and I keep the list short enough that it never feels like a chore."
    "Static pages load fast, break rarely and survive every framework fashion. For notes and small sites, a folder of HTML files and one stylesheet is hard to beat."
    "I moved a small side project from a hosted database to a single SQLite file and nothing bad happened. Reads are quick, backups are a file copy, and deployment got simpler."
    "A backup that has never been restored is a hope, not a plan. Once a month I pick a file at random and restore it to a scratch directory just to see that it works."
    "Most log files are noise. I start with the time window of the problem, filter out the lines that appear every minute, and only then read what is left."
    "Deploy early in the day, change one thing at a time, and always know how to go back. None of this is clever, but it removes most of the stress.")
  local p2=(
    "Unattended security updates cover most of the risk. The rest is remembering what you installed and why, so a short README in the home directory pays for itself."
    "When something does go wrong there is exactly one place to look. That alone is worth the loss of a few conveniences."
    "The limits are real, mostly around concurrent writers, but for a personal tool they never came up."
    "Keep the procedure written down. At the moment you need it you will not remember the flags."
    "A few saved shell one-liners do more than any dashboard I have ever set up."
    "Write the rollback step before you write the deploy step. You will be glad of it the first time something breaks.")

  name="${DOMAIN%%.*}"
  name="$(printf '%s' "${name:0:1}" | tr '[:lower:]' '[:upper:]')${name:1}"
  accent="${accents[RANDOM % ${#accents[@]}]}"
  yr=$(date +%Y)

  rm -rf "$root"
  mkdir -p "$root/posts"

  cat > "$root/style.css" <<EOF
:root{--accent:$accent}
*{box-sizing:border-box}
body{margin:0;font:17px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#1f2937;background:#fff}
header,main,footer{max-width:720px;margin:0 auto;padding:0 20px}
header{display:flex;justify-content:space-between;align-items:center;padding-top:28px;padding-bottom:18px;border-bottom:1px solid #e5e7eb}
.brand{font-weight:700;font-size:1.2em;color:var(--accent);text-decoration:none}
nav a{margin-left:18px;color:#4b5563;text-decoration:none}
nav a:hover,main a:hover{color:var(--accent)}
main{padding-top:26px;padding-bottom:40px}
h1{font-size:1.6em;line-height:1.25;margin:0 0 .6em}
h2{font-size:1.2em;margin:1.6em 0 .2em}
.date{color:#6b7280;font-size:.85em}
main a{color:var(--accent)}
footer{padding-top:18px;padding-bottom:40px;color:#6b7280;font-size:.85em;border-top:1px solid #e5e7eb}
@media (prefers-color-scheme:dark){body{background:#111827;color:#e5e7eb}header,footer{border-color:#374151}nav a{color:#9ca3af}}
EOF

  printf '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="%s"/><text x="32" y="44" font-size="34" font-family="sans-serif" font-weight="700" text-anchor="middle" fill="#fff">%s</text></svg>\n' \
    "$accent" "${name:0:1}" > "$root/favicon.svg"
  printf 'User-agent: *\nAllow: /\n' > "$root/robots.txt"

  n=1
  for i in $(shuf -i 0-5 -n 4); do
    d=$(date -d "-$((RANDOM % 80 + 5)) days" +%Y-%m-%d)
    html_page "${titles[$i]}" "<h1>${titles[$i]}</h1><p class=\"date\">$d</p><p>${p1[$i]}</p><p>${p2[$i]}</p><p><a href=\"/\">&larr; Back to notes</a></p>" > "$root/posts/$n.html"
    list+="<h2><a href=\"/posts/$n.html\">${titles[$i]}</a></h2><p class=\"date\">$d</p><p>${p1[$i]}</p>"
    n=$((n + 1))
  done
  html_page "Notes" "<h1>Notes</h1><p>Short write-ups about running small projects, mostly for my own future reference.</p>$list" > "$root/index.html"
  html_page "About" "<h1>About</h1><p>This is a personal notebook. I write about small servers, simple tools and the habits that keep side projects alive.</p><p>There is no newsletter and no tracking.</p>" > "$root/about.html"
  html_page "Not found" "<h1>Page not found</h1><p>The page you are looking for does not exist. <a href=\"/\">Go back to the notes.</a></p>" > "$root/404.html"

  chmod -R a+rX "$root"
  log "伪装网站已生成: $root ($(du -sk "$root" | cut -f1) KB)"
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
    index index.html;
    limit_rate 512k;
    error_page 404 /404.html;

    location / { try_files \$uri \$uri/ =404; }
    location = /404.html { internal; }
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
      "tag": "vless-xhttp-tls-enc",
      "listen": "$LISTEN",
      "port": $P_XH,
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "$U_XH" } ],
        "decryption": "$D_XH"
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "$CONF_DIR/cert.pem",
              "keyFile": "$CONF_DIR/cert.key"
            }
          ]
        },
        "xhttpSettings": { "path": "/$PATH_XH", "mode": "auto" }
      }
    },
    {
      "tag": "vless-ws-tls-enc",
      "listen": "$LISTEN",
      "port": $P_WS,
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "$U_WS" } ],
        "decryption": "$D_WS"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "$CONF_DIR/cert.pem",
              "keyFile": "$CONF_DIR/cert.key"
            }
          ]
        },
        "wsSettings": { "path": "/$PATH_WS" }
      }
    },
    {
      "tag": "vmess-ws-tls",
      "listen": "$LISTEN",
      "port": $P_VM,
      "protocol": "vmess",
      "settings": { "clients": [ { "id": "$U_VM" } ] },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "$CONF_DIR/cert.pem",
              "keyFile": "$CONF_DIR/cert.key"
            }
          ]
        },
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
  printf 'MODE="%s"\nDOMAIN="%s"\nTCP_PORTS="%s"\nUDP_PORTS="%s"\n' \
    "$MODE" "${DOMAIN:-}" "$tcp" "$P_TUIC $P_HY2" > "$CONF_DIR/ports.env"
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

# ───────────────────────── 节点链接 ─────────────────────────

render_nodes() {
  local n ip vm sb_note tls_note ins_vless="" ins_tuic="" ins_any="" ins_hy="" pin_hy=""
  n="${NODE_NAME:-$(hostname -s)}"
  resolve_ip; ip="$PUBLIC_IP"
  vm=$(printf '{"v":"2","ps":"%s-vmess-ws-tls","add":"%s","port":"%s","id":"%s","aid":"0","scy":"auto","net":"ws","type":"none","host":"%s","path":"/%s","tls":"tls","sni":"%s"}' \
        "$n" "$ip" "$P_VM" "$U_VM" "$CERT_SNI" "$PATH_VM" "$CERT_SNI" | base64 -w0)

  if [ "$MODE" = "selfsteal" ]; then
    tls_note="TLS 正式证书: $DOMAIN (自动续签)"
    sb_note="# ── sing-box (正式证书 $DOMAIN,自动续签;地址用 IP,SNI 用域名) ──"
  else
    tls_note="TLS 自签证书: $CERT_SNI (客户端需开启允许不安全)"
    sb_note="# ── sing-box (自签证书: 客户端需开启\"允许不安全/跳过证书验证\",或使用指纹固定) ──"
    ins_vless="&allowInsecure=1"; ins_tuic="&allow_insecure=1"; ins_any="&insecure=1"; ins_hy="&insecure=1"; pin_hy="&pinSHA256=$CERT_FP"
  fi

  cat > "$CONF_DIR/nodes.txt" <<EOF
# ── Xray ($MODE 模式,Reality SNI: $SNI | $tls_note) ──
vless://$U_VISION@$ip:$P_VISION?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$SNI&fp=chrome&pbk=$R_PUB&sid=$SID&type=tcp&headerType=none#$n-vless-reality-vision

vless://$U_XHR@$ip:$P_XHR?encryption=$E_XHR&security=reality&sni=$SNI&fp=chrome&pbk=$R_PUB&sid=$SID&type=xhttp&path=%2F$PATH_XHR&mode=auto#$n-vless-xhttp-reality-enc

vless://$U_XH@$ip:$P_XH?encryption=$E_XH&security=tls&sni=$CERT_SNI$ins_vless&type=xhttp&path=%2F$PATH_XH&mode=auto#$n-vless-xhttp-tls-enc

vless://$U_WS@$ip:$P_WS?encryption=$E_WS&security=tls&sni=$CERT_SNI$ins_vless&type=ws&path=%2F$PATH_WS#$n-vless-ws-tls-enc

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
    issue_cert
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

  echo
  log "完成。节点链接 (同时保存在 $CONF_DIR/nodes.txt):"
  echo
  cat "$CONF_DIR/nodes.txt"
  echo
  cat <<EOF
注意:
  1. 云厂商面板如果有安全组/防火墙,需放行上面所有 TCP/UDP 端口,以及 UDP $HOP_START-$HOP_END$([ "$MODE" = selfsteal ] && echo ",TCP 80")。
  2. 查看日志: journalctl -u pxy-xray -f    journalctl -u pxy-singbox -f
  3. 再次查看节点: bash pxy-install.sh info
EOF
  if [ "$MODE" = "selfsteal" ]; then
    cat <<EOF
  4. 伪装网站: https://$DOMAIN  (用浏览器打开应看到一个普通博客)
  5. 证书自动续签由 certbot.timer 负责,可用 certbot renew --dry-run 验证续签流程。
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

do_uninstall() {
  [ -d "$CONF_DIR" ] || die "未安装"
  if [ "$ASSUME_YES" -eq 0 ]; then
    read -rp "确认卸载 (将删除所有配置、节点信息和伪装站点)? [y/N] " ans </dev/tty || ans=n
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
    if [ -n "$DOMAIN" ] && command -v certbot >/dev/null; then
      certbot delete --non-interactive --cert-name "$DOMAIN" >/dev/null 2>&1 || true
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
      install|info|upgrade|uninstall) CMD="$a" ;;
      *) die "未知参数: $a" ;;
    esac
  done
  [ "$(id -u)" -eq 0 ] || die "请使用 root 运行"
  if [ "$NO_SERVICE" -eq 1 ]; then NGINX_CONF="$CONF_DIR/nginx-pxy.conf"; fi

  case "$CMD" in
    install)   do_install ;;
    info)      do_info ;;
    upgrade)   do_upgrade ;;
    uninstall) do_uninstall ;;
  esac
}

# 被 source 时 (测试) 不自动执行
if [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; fi
