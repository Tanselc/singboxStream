#!/bin/bash

# 安装 Sing-Box
install_singbox() {
  echo "正在安装 Sing-Box..."
  bash <(curl -fsSL https://sing-box.app/deb-install.sh)
}

# 安装 warp
install_warp() {
  echo "正在安装 warp，端口一定要默认40000，选13"
  bash <(curl -fsSL https://gitlab.com/fscarmen/warp_unlock/-/raw/main/unlock.sh)
}

# 检查并启动长期运行的 HTTP 服务
start_http_server() {
  # HTTP 服务监听的目录
  HTTP_DIR="/root"
  PORT=8080

  # 检查端口是否被占用
  PID=$(lsof -t -i :$PORT)
  if [[ -z "$PID" ]]; then
    echo "正在启动长期运行的 HTTP 服务..."
    cd "$HTTP_DIR"
    nohup python3 -m http.server $PORT > /dev/null 2>&1 &
    echo "HTTP 服务已启动，监听端口 $PORT"
  else
    echo "HTTP 服务已运行，监听端口 $PORT (进程 $PID)"
  fi
}

# 提供下载链接
provide_download_link() {
  PORT=8080
  SERVER_IP=$(curl -s ifconfig.me)

  echo "文件已生成并可通过以下链接下载："
  echo "http://$SERVER_IP:$PORT/singbox.yaml"
}

# 配置服务端 config.json
configure_singbox() {
  CONFIG_PATH="/etc/sing-box/config.json"

  # 提示用户输入 SERVER 值
  read -p "请输入服务器地址 (如 www.example.com，留空则根据地区自动设置): " SERVER

  # 如果用户未输入，询问服务器所在地
  if [[ -z "$SERVER" ]]; then
    echo "未输入服务器地址，请选择服务器所在地:"
    echo "1) 日本"
    echo "2) 洛杉矶"
    read -p "请选择 (1/2): " LOCATION
    case $LOCATION in
      1)
        SERVER="www.lovelive-anime.jp"
        ;;
      2)
        SERVER="www.thewaltdisneycompany.com"
        ;;
      *)
        echo "输入无效，默认选择苹果服务器。"
        SERVER="www.apple.com"
        ;;
    esac
  fi
  # 询问是否启用 ChatGPT 分流
  read -p "是否启用 ChatGPT 分流? (y/n): " ENABLE_CHATGPT
  # 准备路由规则
  if [[ "${ENABLE_CHATGPT}" == "y" ]]; then
    install_warp
    CHATGPT_RULES='{
        "rule_set": ["geosite-chatgpt"],
        "outbound": "socks-netflix"
      },
      {
        "domain": ["nodeseek.com"],
        "outbound": "socks-netflix"
      },'
  else
    CHATGPT_RULES=""
  fi

  # 生成完整 config.json 文件
  cat > $CONFIG_PATH <<EOF
{
  "log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "local",
        "address": "https://1.1.1.1/dns-query",
        "detour": "direct"
      },
      {
        "tag": "block",
        "address": "rcode://success"
      }
    ],
    "rules": [
      {
        "geosite": "cn",
        "server": "local"
      },
      {
        "geosite": "category-ads-all",
        "server": "block",
        "disable_cache": true
      }
    ]
  },
  "inbounds": [
    {
      "type": "shadowtls",
      "tag": "st-in",
      "listen": "::",
      "listen_port": 443,
      "version": 3,
      "users": [
        {
          "name": "username",
          "password": "AaaY/lgWSBlSQtDmd0UpFnqR1JJ9JTHn0CLBv12KO5o="
        }
      ],
      "handshake": {
        "server": "$SERVER",
        "server_port": 443
      },
      "strict_mode": true,
      "detour": "ss-in"
    },
    {
      "type": "shadowsocks",
      "tag": "ss-in",
      "listen": "127.0.0.1",
      "network": "tcp",
      "method": "2022-blake3-chacha20-poly1305",
      "password": "Aq2bNFEAtpW8EQcLmU5v43cxyYDHlh6U7qg5NHxS51w="
    },
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": 10242,
      "users": [
        {
          "uuid": "8e65722e-7813-47a1-9472-2db594575b27",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "$SERVER",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "$SERVER",
            "server_port": 443
          },
          "private_key": "QNJo_UznAk69XQeWNKtY-RdsfzJE-s5uAFso5tARWkA",
          "short_id": [
            "0123456789abcded"
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    },
    {
      "type": "socks",
      "tag": "socks-netflix",
      "server": "127.0.0.1",
      "server_port": 40000
    }
  ],
  "route": {
    "geoip": {
      "download_url": "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db",
      "download_detour": "direct"
    },
    "geosite": {
      "download_url": "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db",
      "download_detour": "direct"
    },
    "rules": [
      $CHATGPT_RULES
      {
        "geosite": "cn",
        "geoip": "cn",
        "outbound": "direct"
      },
      {
        "geosite": "category-ads-all",
        "outbound": "block"
      }
    ],
    "rule_set": [
      {
        "tag": "geosite-chatgpt",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-openai.srs",
        "download_detour": "direct"
      }
    ]
  }
}
EOF
  echo "服务端配置文件已保存到 $CONFIG_PATH"
}

# 启用并启动 Sing-Box 服务
enable_and_start_service() {
  echo "启用并启动 Sing-Box 服务..."
  sudo systemctl enable sing-box
  sudo systemctl start sing-box
  echo "Sing-Box 服务已启用并启动。"
}

serve_download() {
  CONFIG_PATH="/root/singbox.yaml"

  if [[ ! -f $CONFIG_PATH ]]; then
    echo "错误：文件 $CONFIG_PATH 不存在，无法提供下载。"
    exit 1
  fi

  echo "正在启动文件下载服务..."
  
  # 启动 Python 的 HTTP 服务，默认监听端口 8080

  python3 -m http.server 8080 --directory /root >/dev/null 2>&1 &
  SERVER_PID=$!

  # 获取服务器公网 IP
  SERVER_IP=$(curl -s ifconfig.me || echo "localhost")
  
  # 提示下载地址
  echo "文件已生成并可通过以下链接下载："
  echo "http://$SERVER_IP:8080/singbox.yaml"

  echo "按 Ctrl+C 停止下载服务。"

  # 等待用户手动终止
  wait $SERVER_PID
}

generate_v2ray_link() {
  # 使用之前已经获取的值
  V2RAY_UUID="8e65722e-7813-47a1-9472-2db594575b27"
  V2RAY_IP="$SERVER_IP"
  V2RAY_HOST="$SERVER"
  V2RAY_PBK="Y_-yCHC3Qi-Kz6OWpueQckAJSQuGEKffwWp8MlFgwTs"
  V2RAY_SID="0123456789abcded"

  # 生成 V2Ray 链接
  V2RAY_LINK="vless://${V2RAY_UUID}@${V2RAY_IP}:10242?security=reality&flow=xtls-rprx-vision&type=tcp&sni=${V2RAY_HOST}&fp=chrome&pbk=${V2RAY_PBK}&sid=${V2RAY_SID}&encryption=none&headerType=none#reality"

  echo "生成的 V2Ray 链接："
  echo "$V2RAY_LINK"
}

cleanup_port() {
  PORT=8080
  PID=$(sudo lsof -t -i :$PORT) # 获取占用端口的进程 ID
  if [[ -n "$PID" ]]; then
    echo "端口 $PORT 已被进程 $PID 占用，正在终止..."
    sudo kill -9 $PID
    echo "端口 $PORT 已释放。"
  fi
}

generate_qr_code() {
  echo "正在生成二维码..."

  # 检查是否安装 qrencode
  if ! command -v qrencode >/dev/null 2>&1; then
    echo "未安装 qrencode，正在安装..."
    sudo apt-get update && sudo apt-get install -y qrencode
  fi

  # 在终端显示二维码
  echo "二维码已生成，请扫描以下二维码："
  qrencode -t ANSIUTF8 "$V2RAY_LINK"

  echo "二维码生成完成！"
}



# 生成客户端配置文件 singbox.yaml
generate_client_config() {
  CONFIG_PATH="/root/singbox.yaml"

  # 获取当前机器的公网 IP
  SERVER_IP=$(curl -s ifconfig.me || curl -s ipinfo.io/ip)
  if [[ -z "$SERVER_IP" ]]; then
    echo "无法获取服务器的公网 IP 地址，请检查网络连接。"
    exit 1
  fi

  # 使用之前输入的 SERVER 值
  HOST="$SERVER"
  SERVERNAME="$SERVER"

  # 生成客户端配置文件
  cat > $CONFIG_PATH <<EOF
# 客户端配置文件
# port: 7890 # HTTP(S) 代理服务器端口
# socks-port: 7891 # SOCKS5 代理端口
mixed-port: 10801 # HTTP(S) 和 SOCKS 代理混合端口
# redir-port: 7892 # 透明代理端口，用于 Linux 和 MacOS
# Transparent proxy server port for Linux (TProxy TCP and TProxy UDP)
# tproxy-port: 7893
allow-lan: true # 允许局域网连接
bind-address: "*" # 绑定 IP 地址，仅作用于 allow-lan 为 true，'*'表示所有地址
# find-process-mode has 3 values:always, strict, off
# - always, 开启，强制匹配所有进程
# - strict, 默认，由 clash 判断是否开启
# - off, 不匹配进程，推荐在路由器上使用此模式
find-process-mode: strict
mode: rule
#自定义 geodata url
geox-url:
  geoip: "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat"
  geosite: "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat"
  mmdb: "https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb"
log-level: debug # 日志等级 silent/error/warning/info/debug
ipv6: true # 开启 IPv6 总开关，关闭阻断所有 IPv6 链接和屏蔽 DNS 请求 AAAA 记录
external-controller: 0.0.0.0:9093 # RESTful API 监听地址
secret: "123456" # RESTful API的密码 (可选)
# tcp-concurrent: true # TCP 并发连接所有 IP, 将使用最快握手的 TCP
#external-ui: /path/to/ui/folder # 配置 WEB UI 目录，使用 http://{{external-controller}}/ui 访问
# interface-name: en0 # 设置出口网卡
# 全局 TLS 指纹，优先低于 proxy 内的 client-fingerprint
# 可选： "chrome","firefox","safari","ios","random","none" options.
# Utls is currently support TLS transport in TCP/grpc/WS/HTTP for VLESS/Vmess and trojan.
global-client-fingerprint: chrome
# routing-mark:6666 # 配置 fwmark 仅用于 Linux
# 实验性选择
# experimental:
# 类似于 /etc/hosts, 仅支持配置单个 IP
# hosts:
  # '*.clash.dev': 127.0.0.1
  # '.dev': 127.0.0.1
  # 'alpha.clash.dev': '::1'
  # test.com: [1.1.1.1, 2.2.2.2]
  # clash.lan: clash # clash 为特别字段，将加入本地所有网卡的地址
  # baidu.com: google.com # 只允许配置一个别名
profile: # 存储 select 选择记录
  store-selected: true
  # 持久化 fake-ip
  store-fake-ip: true
# 嗅探域名
sniffer:
  enable: true
  sniffing:
    - tls
    - http
  # 强制对此域名进行嗅探
dns:
  enable: true #开启Clash内置DNS服务器，默认为false
  prefer-h3: true # 开启 DoH 支持 HTTP/3，将并发尝试
  listen: 0.0.0.0:53 # 开启 DNS 服务器监听
  ipv6: true # false 将返回 AAAA 的空结果
  # ipv6-timeout: 300 # 单位：ms，内部双栈并发时，向上游查询 AAAA 时，等待 AAAA 的时间，默认 100ms
  # 解析nameserver和fallback的DNS服务器
  # 填入纯IP的DNS服务器
  default-nameserver:
    - 114.114.114.114
    - 223.5.5.5
  enhanced-mode: fake-ip # 模式fake-ip
  fake-ip-range: 198.18.0.1/16 # fake-ip 池设置
  # use-hosts: true # 查询 hosts
  # 配置不使用fake-ip的域名
  fake-ip-filter:
    - "*.lan"
    - "*.localdomain"
    - "*.example"
    - "*.invalid"
    - "*.localhost"
    - "*.test"
    - "*.local"
    - "*.home.arpa"
    - time.*.com
    - time.*.gov
    - time.*.edu.cn
    - time.*.apple.com
    - time1.*.com
    - time2.*.com
    - time3.*.com
    - time4.*.com
    - time5.*.com
    - time6.*.com
    - time7.*.com
    - ntp.*.com
    - ntp1.*.com
    - ntp2.*.com
    - ntp3.*.com
    - ntp4.*.com
    - ntp5.*.com
    - ntp6.*.com
    - ntp7.*.com
    - "*.time.edu.cn"
    - "*.ntp.org.cn"
    - "+.pool.ntp.org"
    - music.163.com
    - "*.music.163.com"
    - "*.126.net"
    - musicapi.taihe.com
    - music.taihe.com
    - songsearch.kugou.com
    - trackercdn.kugou.com
    - "*.kuwo.cn"
    - api-jooxtt.sanook.com
    - api.joox.com
    - joox.com
    - y.qq.com
    - "*.y.qq.com"
    - streamoc.music.tc.qq.com
    - mobileoc.music.tc.qq.com
    - isure.stream.qqmusic.qq.com
    - dl.stream.qqmusic.qq.com
    - aqqmusic.tc.qq.com
    - amobile.music.tc.qq.com
    - "*.xiami.com"
    - "*.music.migu.cn"
    - music.migu.cn
    - "*.msftconnecttest.com"
    - "*.msftncsi.com"
    - msftconnecttest.com
    - msftncsi.com
    - localhost.ptlogin2.qq.com
    - localhost.sec.qq.com
    - "+.srv.nintendo.net"
    - "+.stun.playstation.net"
    - xbox.*.microsoft.com
    - xnotify.xboxlive.com
    - "+.battlenet.com.cn"
    - "+.wotgame.cn"
    - "+.wggames.cn"
    - "+.wowsgame.cn"
    - "+.jd.com"
    - "+.wargaming.net"
    - proxy.golang.org
    - stun.*.*
    - stun.*.*.*
    - "+.stun.*.*"
    - "+.stun.*.*.*"
    - "+.stun.*.*.*.*"
    - heartbeat.belkin.com
    - "*.linksys.com"
    - "*.linksyssmartwifi.com"
    - "*.router.asus.com"
    - mesu.apple.com
    - swscan.apple.com
    - swquery.apple.com
    - swdownload.apple.com
    - swcdn.apple.com
    - swdist.apple.com
    - lens.l.google.com
    - stun.l.google.com
    - "+.nflxvideo.net"
    - "*.square-enix.com"
    - "*.finalfantasyxiv.com"
    - "*.ffxiv.com"
    - '*.mcdn.bilivideo.cn'
  # DNS主要域名配置
  # 支持 UDP，TCP，DoT，DoH，DoQ
  # 这部分为主要 DNS 配置，影响所有直连，确保使用对大陆解析精准的 DNS
  nameserver:
    - 114.114.114.114 # default value
    - 223.5.5.5
    - 119.29.29.29
    - https://doh.360.cn/dns-query
    - https://doh.pub/dns-query # DNS over HTTPS
    - https://dns.alidns.com/dns-query # 强制 HTTP/3，与 perfer-h3 无关，强制开启 DoH 的 HTTP/3 支持，若不支持将无法使用
  # 当配置 fallback 时，会查询 nameserver 中返回的 IP 是否为 CN，非必要配置
  # 当不是 CN，则使用 fallback 中的 DNS 查询结果
  # 确保配置 fallback 时能够正常查询
  fallback:
    - 219.141.136.10
    - 8.8.8.8
    - 1.1.1.1
    - https://cloudflare-dns.com/dns-query
    - https://dns.google/dns-query
  # 配置 fallback 使用条件
  fallback-filter:
    geoip: false # 配置是否使用 geoip
    geoip-code: CN # 当 nameserver 域名的 IP 查询 geoip 库为 CN 时，不使用 fallback 中的 DNS 查询结果
  # 如果不匹配 ipcidr 则使用 nameservers 中的结果
    ipcidr:
      - 240.0.0.0/4
    domain:
      - "+.google.com"
      - "+.facebook.com"
      - "+.youtube.com"
      - "+.githubusercontent.com"
      - "+.googlevideo.com"
proxies:
- name: ShadowTLS v3
  type: ss
  server: $SERVER_IP
  port: 443
  cipher: 2022-blake3-chacha20-poly1305
  password: "Nq2bNFEAtpW8EQcLmU5v43cxyYDHlh6U7qg5NHxS51w="
  plugin: shadow-tls
  client-fingerprint: chrome
  plugin-opts:
    host: "$SERVER"
    password: "BaaY/lgWSBlSQtDmd0UpFnqR1JJ9JTHn0CLBv12KO5o="
    version: 3
- name: reality
  type: vless
  server: $SERVER_IP
  port: 10242
  uuid: 8e65722e-7813-47a1-9472-2db594575b27
  network: tcp
  udp: true
  tls: true
  flow: xtls-rprx-vision
  servername: $SERVER
  client-fingerprint: chrome
  reality-opts:
    public-key: Y_-yCHC3Qi-Kz6OWpueQckAJSQuGEKffwWp8MlFgwTs
    short-id: 0123456789abcded
proxy-groups:
- name: PROXY
  type: select
  proxies:
    - reality
rule-providers:
  reject:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt"
    path: ./ruleset/reject.yaml
    interval: 86400
  icloud:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/icloud.txt"
    path: ./ruleset/icloud.yaml
    interval: 86400
  apple:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/apple.txt"
    path: ./ruleset/apple.yaml
    interval: 86400
  proxy:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt"
    path: ./ruleset/proxy.yaml
    interval: 86400
  direct:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt"
    path: ./ruleset/direct.yaml
    interval: 86400
  private:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt"
    path: ./ruleset/private.yaml
    interval: 86400
  gfw:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt"
    path: ./ruleset/gfw.yaml
    interval: 86400
  greatfire:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/greatfire.txt"
    path: ./ruleset/greatfire.yaml
    interval: 86400
  tld-not-cn:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/tld-not-cn.txt"
    path: ./ruleset/tld-not-cn.yaml
    interval: 86400
  telegramcidr:
    type: http
    behavior: ipcidr
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/telegramcidr.txt"
    path: ./ruleset/telegramcidr.yaml
    interval: 86400
  cncidr:
    type: http
    behavior: ipcidr
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt"
    path: ./ruleset/cncidr.yaml
    interval: 86400
  lancidr:
    type: http
    behavior: ipcidr
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt"
    path: ./ruleset/lancidr.yaml
    interval: 86400
  applications:
    type: http
    behavior: classical
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/applications.txt"
    path: ./ruleset/applications.yaml
    interval: 86400
rules:
  - RULE-SET,applications,DIRECT
  - DOMAIN,clash.razord.top,DIRECT
  - DOMAIN,yacd.haishan.me,DIRECT
  - DOMAIN-SUFFIX,stream1.misakaf.org:443,PROXY
  - DOMAIN-SUFFIX,stream2.misakaf.org:443,PROXY
  - DOMAIN-SUFFIX,stream3.misakaf.org:443,PROXY
  - DOMAIN-SUFFIX,stream4.misakaf.org:443,PROXY
  - DOMAIN-SUFFIX,services.googleapis.cn,DIRECT
  - DOMAIN-SUFFIX,xn--ngstr-lra8j.com,DIRECT
  - RULE-SET,private,DIRECT
  - RULE-SET,reject,REJECT
  - RULE-SET,icloud,DIRECT
  - RULE-SET,apple,DIRECT
  - RULE-SET,proxy,PROXY
  - RULE-SET,direct,DIRECT
  - RULE-SET,lancidr,DIRECT
  - RULE-SET,cncidr,DIRECT
  - RULE-SET,telegramcidr,PROXY
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
EOF
  echo "客户端配置文件已生成并保存到 $CONFIG_PATH"
}

# 主函数
main() {
  install_singbox
  configure_singbox
  enable_and_start_service
  generate_client_config
  start_http_server 
  provide_download_link
  generate_v2ray_link
  generate_qr_code
  serve_download
  echo "所有配置完成！"
}

main
