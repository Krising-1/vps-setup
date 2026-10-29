#!/usr/bin/env bash
# =============================================================================
#  server-setup.sh — интерактивная базовая настройка и защита чистого VPS
#  Целевая система: Ubuntu 24.04 LTS
#
#  Что делает (всё по вопросам, можно пропускать):
#    - обновляет систему, ставит базовые пакеты, автообновления безопасности
#    - создаёт отдельного sudo-пользователя, добавляет SSH-ключ
#      (вставить / с GitHub / сгенерировать на сервере)
#    - переводит SSH на классическую службу (отключает ssh.socket),
#      меняет порт, отключает вход по паролю, ограничивает root
#    - настраивает UFW (default deny incoming + нужные порты)
#    - ставит и настраивает Fail2Ban (systemd-журнал, порт SSH)
#    - по желанию: sysctl-харденинг, BBR, swap, часовой пояс
#
#  Безопасность от «самозапирания»:
#    - перед отключением паролей проверяется, что есть рабочий ключ
#    - новый порт проверяется ДО закрытия старого: вы подключаетесь во втором
#      окне, и только после подтверждения старые порты закрываются
#    - если проверка не пройдена — SSH откатывается к прежним настройкам
#
#  Запуск (из интерактивной SSH-сессии, от root или через sudo):
#    sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/<you>/<repo>/main/server-setup.sh)"
#  или:
#    curl -fsSLO https://raw.githubusercontent.com/<you>/<repo>/main/server-setup.sh
#    sudo bash server-setup.sh
# =============================================================================

set -Eeuo pipefail

SCRIPT_VERSION="1.0.0"
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

APT_OPTS=(-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o DPkg::Lock::Timeout=180)
HARDENING_CONF="/etc/ssh/sshd_config.d/00-hardening.conf"
BACKUP_DIR="/root/server-setup-backup-$(date +%Y%m%d-%H%M%S)"
SUMMARY_FILE="/root/server-setup-summary.txt"

# ----------------------------- оформление ------------------------------------
if [[ -t 1 ]]; then
  C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'; C_BLU=$'\e[36m'; C_BLD=$'\e[1m'; C_OFF=$'\e[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_BLD=""; C_OFF=""
fi

info() { printf '%s➜%s %s\n' "$C_BLU" "$C_OFF" "$*"; }
ok()   { printf '%s✔%s %s\n' "$C_GRN" "$C_OFF" "$*"; }
warn() { printf '%s⚠%s %s\n' "$C_YEL" "$C_OFF" "$*" >&2; }
err()  { printf '%s✖%s %s\n' "$C_RED" "$C_OFF" "$*" >&2; }
die()  { err "$*"; exit 1; }
step() { printf '\n%s== %s ==%s\n' "$C_BLD" "$*" "$C_OFF"; }

trap 'err "Ошибка на строке $LINENO (команда: $BASH_COMMAND). Скрипт остановлен."' ERR

# ----------------------------- переменные ------------------------------------
SSH_PORT=22
CUR_PORTS=()
CLIENT_IP=""
CREATE_USER=no
NEW_USER=""
SUDO_MODE="password"
TARGET_USER="root"
KEY_MODE="none"            # none | add | generate
NEW_KEYS=()
ROOT_LOGIN="prohibit-password"
DISABLE_PW=no
MAX_AUTH=4
LOGIN_GRACE=30
MAX_STARTUPS="10:30:60"
DO_UPGRADE=yes
DO_AUTOUPD=yes
TZ_NEW=""
DO_UFW=yes
EXTRA_PORTS=()
DO_F2B=yes
F2B_MAXRETRY=3
F2B_BANTIME="1h"
F2B_FINDTIME="10m"
F2B_IGNORE=""
DO_SYSCTL=yes
DO_BBR=yes
SWAP_GB=0
SSH_BACKED_UP=no

# ----------------------------- ввод ------------------------------------------
ask() { # ask VAR "Вопрос" "по умолчанию"
  local __v=$1 q=$2 d=${3-} r
  if [[ -n $d ]]; then
    read -r -p "$q [$d]: " r </dev/tty || die "Ввод прерван"
  else
    read -r -p "$q: " r </dev/tty || die "Ввод прерван"
  fi
  printf -v "$__v" '%s' "${r:-$d}"
}

ask_yn() { # ask_yn "Вопрос" y|n   -> код 0 если «да»
  local q=$1 d=${2:-y} r hint
  if [[ $d == y ]]; then hint="Y/n"; else hint="y/N"; fi
  while true; do
    read -r -p "$q [$hint]: " r </dev/tty || die "Ввод прерван"
    r=${r:-$d}
    case ${r,,} in
      y|yes|д|да) return 0 ;;
      n|no|н|нет) return 1 ;;
    esac
    echo "Ответьте y или n"
  done
}

ask_choice() { # ask_choice VAR "Вопрос" default max
  local __v=$1 q=$2 d=$3 max=$4 r
  while true; do
    read -r -p "$q [$d]: " r </dev/tty || die "Ввод прерван"
    r=${r:-$d}
    if [[ $r =~ ^[0-9]+$ ]] && (( r >= 1 && r <= max )); then
      printf -v "$__v" '%s' "$r"
      return 0
    fi
    echo "Введите число от 1 до $max"
  done
}

# ----------------------------- утилиты ---------------------------------------
in_array() { local n=$1 x; shift; for x in "$@"; do if [[ $x == "$n" ]]; then return 0; fi; done; return 1; }

valid_port() { [[ $1 =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

port_in_use() { ss -Htln "sport = :$1" 2>/dev/null | grep -q .; }

trim() { printf '%s' "$1" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }

valid_pubkey() { # публичный ключ в формате OpenSSH, одна строка
  local k=$1 tmp rc=1
  [[ $k =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9]+|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)[[:space:]]+[A-Za-z0-9+/=]+ ]] || return 1
  tmp=$(mktemp)
  printf '%s\n' "$k" >"$tmp"
  if ssh-keygen -l -f "$tmp" >/dev/null 2>&1; then rc=0; fi
  rm -f "$tmp"
  return $rc
}

user_exists() { id "$1" &>/dev/null; }

user_home() { getent passwd "$1" | cut -d: -f6; }

user_has_keys() {
  local home f
  user_exists "$1" || return 1
  home=$(user_home "$1")
  f="$home/.ssh/authorized_keys"
  [[ -s $f ]] && grep -Eqv '^[[:space:]]*(#|$)' "$f"
}

server_ip() {
  local ip=""
  ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}') || true
  if [[ -z $ip ]]; then ip=$(hostname -I 2>/dev/null | awk '{print $1}') || true; fi
  printf '%s' "${ip:-IP_СЕРВЕРА}"
}

detect_current_ssh_ports() {
  local p
  CUR_PORTS=()
  if [[ -n ${SSH_CONNECTION:-} ]]; then
    p=$(awk '{print $4}' <<<"$SSH_CONNECTION")
    if valid_port "$p" && ! in_array "$p" "${CUR_PORTS[@]}"; then CUR_PORTS+=("$p"); fi
    CLIENT_IP=$(awk '{print $1}' <<<"$SSH_CONNECTION")
  fi
  if command -v sshd >/dev/null 2>&1; then
    while read -r p; do
      if [[ -n $p ]] && valid_port "$p" && ! in_array "$p" "${CUR_PORTS[@]}"; then CUR_PORTS+=("$p"); fi
    done < <(sshd -T 2>/dev/null | awk '$1=="port"{print $2}')
  fi
  if ! in_array 22 "${CUR_PORTS[@]}"; then CUR_PORTS+=(22); fi
}

usage() {
  cat <<EOF
server-setup.sh v$SCRIPT_VERSION — интерактивная защита чистого VPS (Ubuntu 24.04)

Запуск:  sudo bash server-setup.sh
Ключи:   -h, --help  эта справка

Скрипт задаёт вопросы, показывает итоговый план и только после подтверждения
вносит изменения. Резервные копии конфигов: $BACKUP_DIR
EOF
}

# ----------------------------- проверки --------------------------------------
preflight() {
  (( EUID == 0 )) || die "Запустите от root: sudo bash server-setup.sh"
  { : </dev/tty; } 2>/dev/null || die "Нет терминала (/dev/tty). Запускайте из интерактивной SSH-сессии."
  [[ -d /run/systemd/system ]] || die "Нужен systemd (контейнеры без systemd не поддерживаются)."

  local os_id os_ver virt
  os_id=$(. /etc/os-release 2>/dev/null; echo "${ID:-}")
  os_ver=$(. /etc/os-release 2>/dev/null; echo "${VERSION_ID:-}")
  if [[ $os_id != ubuntu ]]; then
    warn "Скрипт рассчитан на Ubuntu 24.04, у вас: ${os_id:-неизвестно} ${os_ver}"
    ask_yn "Всё равно продолжить?" n || exit 1
  elif [[ $os_ver != 24.04 ]]; then
    warn "Скрипт рассчитан на Ubuntu 24.04, у вас: $os_ver (должно работать, но не проверялось)"
  fi

  virt=$(systemd-detect-virt 2>/dev/null || true)
  case $virt in
    lxc|openvz|systemd-nspawn|docker)
      warn "Обнаружен контейнер ($virt): sysctl, swap и BBR могут быть недоступны — такие шаги будут пропущены при ошибке." ;;
  esac
}

# ----------------------------- вопросы ---------------------------------------
q_ssh_port() {
  step "Порт SSH"
  local def
  def=$(shuf -i 10000-60000 -n 1)
  while port_in_use "$def"; do def=$(shuf -i 10000-60000 -n 1); done
  while true; do
    ask SSH_PORT "Порт SSH (22 — стандартный; рекомендую 10000-60000)" "$def"
    if ! valid_port "$SSH_PORT"; then warn "Порт — число от 1 до 65535"; continue; fi
    SSH_PORT=$((10#$SSH_PORT))
    if (( SSH_PORT < 1024 && SSH_PORT != 22 )); then
      warn "Привилегированные порты (<1024), кроме 22, лучше не использовать"; continue
    fi
    if port_in_use "$SSH_PORT" && ! in_array "$SSH_PORT" "${CUR_PORTS[@]}"; then
      warn "Порт $SSH_PORT уже занят другой программой"; continue
    fi
    break
  done
}

q_user() {
  step "Пользователь"
  if ask_yn "Создать отдельного пользователя с sudo (рекомендуется, чтобы не работать под root)?" y; then
    CREATE_USER=yes
    while true; do
      ask NEW_USER "Имя пользователя" "admin"
      if [[ ! $NEW_USER =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then warn "Допустимы строчные латинские буквы, цифры, _ и -"; continue; fi
      if [[ $NEW_USER == root ]]; then warn "Нужно имя, отличное от root"; continue; fi
      break
    done
    if user_exists "$NEW_USER"; then info "Пользователь $NEW_USER уже существует — будет использован."; fi
    echo "Как должен работать sudo для $NEW_USER?"
    echo "  1) с паролем (пароль зададите в процессе; нужен только для sudo)"
    echo "  2) без пароля (NOPASSWD) — удобнее, защита держится на SSH-ключе"
    local c
    ask_choice c "Выбор" 1 2
    if [[ $c == 2 ]]; then SUDO_MODE="nopasswd"; else SUDO_MODE="password"; fi
    TARGET_USER=$NEW_USER
  else
    while true; do
      ask TARGET_USER "Для какого пользователя настраиваем вход по ключу" "${SUDO_USER:-root}"
      if user_exists "$TARGET_USER"; then break; fi
      warn "Пользователь $TARGET_USER не найден"
    done
  fi
}

collect_github_keys() {
  local gh data line n=0
  ask gh "Логин на GitHub" ""
  if [[ ! $gh =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,38})$ ]]; then warn "Некорректный логин"; return 0; fi
  if ! data=$(curl -fsSL --max-time 15 "https://github.com/${gh}.keys"); then
    warn "Не удалось получить https://github.com/${gh}.keys"; return 0
  fi
  while IFS= read -r line; do
    line=$(trim "$line")
    [[ -n $line ]] || continue
    if valid_pubkey "$line"; then NEW_KEYS+=("$line"); n=$((n + 1)); fi
  done <<<"$data"
  if (( n > 0 )); then ok "Получено ключей: $n"; else warn "У пользователя нет подходящих публичных ключей"; fi
}

collect_pasted_keys() {
  local line
  echo "Вставьте публичный ключ (одной строкой: ssh-ed25519 AAAA... или ssh-rsa AAAA...)."
  echo "В MobaXterm это текст из верхнего окна MobaKeyGen. Пустая строка — закончить."
  while true; do
    ask line "Публичный ключ" ""
    line=$(trim "$line")
    [[ -n $line ]] || break
    if valid_pubkey "$line"; then
      NEW_KEYS+=("$line"); ok "Ключ принят"
    else
      warn "Это не похоже на корректный публичный ключ (приватный ключ вставлять нельзя!)"
    fi
  done
}

q_keys() {
  step "SSH-ключи для пользователя $TARGET_USER"
  local def=1 c
  if user_has_keys "$TARGET_USER"; then
    ok "У $TARGET_USER уже есть ключи в authorized_keys"
    def=4
  fi
  echo "  1) Вставить публичный ключ (сгенерируйте на своём ПК: MobaKeyGen / ssh-keygen)"
  echo "  2) Загрузить с GitHub (https://github.com/<логин>.keys)"
  echo "  3) Сгенерировать пару на сервере и показать приватный ключ (менее безопасно)"
  echo "  4) Ничего не добавлять"
  ask_choice c "Выбор" "$def" 4
  case $c in
    1) collect_pasted_keys ;;
    2) collect_github_keys ;;
    3) KEY_MODE="generate" ;;
    4) ;;
  esac
  if (( ${#NEW_KEYS[@]} > 0 )); then KEY_MODE="add"; fi
}

q_ssh_hardening() {
  step "Защита SSH"
  # root
  if [[ $TARGET_USER == root ]]; then
    ROOT_LOGIN="prohibit-password"
    info "Ключ настраивается для root, поэтому root будет входить только по ключу."
  elif ask_yn "Полностью запретить вход root по SSH? (рекомендуется)" y; then
    ROOT_LOGIN="no"
  else
    ROOT_LOGIN="prohibit-password"
  fi

  # есть ли вообще рабочий ключ
  local have_key=no
  if user_has_keys "$TARGET_USER" || [[ $KEY_MODE != none ]]; then have_key=yes; fi
  if [[ $ROOT_LOGIN != no ]] && user_has_keys root; then have_key=yes; fi

  if [[ $have_key == yes ]]; then
    if ask_yn "Отключить вход по паролю (останется только вход по ключу)?" y; then DISABLE_PW=yes; fi
  else
    warn "Ни у одного пользователя нет SSH-ключа — вход по паролю останется ВКЛЮЧЁН, иначе вы запрёте себя."
    DISABLE_PW=no
  fi

  if ask_yn "Изменить тонкие параметры (MaxAuthTries, LoginGraceTime, MaxStartups)?" n; then
    while true; do ask MAX_AUTH "MaxAuthTries — попыток аутентификации на соединение" "$MAX_AUTH"; [[ $MAX_AUTH =~ ^[0-9]+$ ]] && break; warn "Нужно число"; done
    while true; do ask LOGIN_GRACE "LoginGraceTime — секунд на вход" "$LOGIN_GRACE"; [[ $LOGIN_GRACE =~ ^[0-9]+$ ]] && break; warn "Нужно число"; done
    while true; do ask MAX_STARTUPS "MaxStartups start:rate:full" "$MAX_STARTUPS"; [[ $MAX_STARTUPS =~ ^[0-9]+:[0-9]+:[0-9]+$ ]] && break; warn "Формат: 10:30:60"; done
  fi
}

q_firewall() {
  step "Фаервол (UFW)"
  if ! ask_yn "Настроить UFW (закрыть всё входящее, кроме SSH и указанных портов)?" y; then
    DO_UFW=no; return 0
  fi
  local line tok
  echo "Какие ещё порты открыть? Через пробел, например: 443/tcp 80/tcp 51820/udp"
  echo "Без /tcp или /udp — откроется и то, и другое. Пусто — только SSH."
  while true; do
    ask line "Дополнительные порты" ""
    EXTRA_PORTS=()
    local bad=no
    for tok in $line; do
      if [[ $tok =~ ^([0-9]{1,5})(:([0-9]{1,5}))?(/(tcp|udp))?$ ]] \
         && (( 10#${BASH_REMATCH[1]} >= 1 && 10#${BASH_REMATCH[1]} <= 65535 )) \
         && { [[ -z ${BASH_REMATCH[3]} ]] || (( 10#${BASH_REMATCH[3]} <= 65535 )); }; then
        EXTRA_PORTS+=("$tok")
      else
        warn "Некорректный порт: $tok"; bad=yes
      fi
    done
    [[ $bad == no ]] && break
  done
}

q_fail2ban() {
  step "Fail2Ban"
  if ! ask_yn "Установить и настроить Fail2Ban (автобан подбирающих пароли)?" y; then
    DO_F2B=no; return 0
  fi
  while true; do ask F2B_MAXRETRY "Сколько неудачных попыток до бана" "$F2B_MAXRETRY"; [[ $F2B_MAXRETRY =~ ^[0-9]+$ ]] && (( F2B_MAXRETRY > 0 )) && break; warn "Нужно число > 0"; done
  while true; do ask F2B_BANTIME "Срок бана (1h, 12h, 1d ...)" "$F2B_BANTIME"; [[ $F2B_BANTIME =~ ^[0-9]+[smhdw]?$ ]] && break; warn "Пример: 1h"; done
  while true; do ask F2B_FINDTIME "Окно подсчёта попыток (10m ...)" "$F2B_FINDTIME"; [[ $F2B_FINDTIME =~ ^[0-9]+[smhdw]?$ ]] && break; warn "Пример: 10m"; done
  ask F2B_IGNORE "IP, которые никогда не банить (через пробел; ваш текущий IP — защита от самобана)" "$CLIENT_IP"
}

q_system() {
  step "Система"
  if ask_yn "Обновить пакеты (apt upgrade)?" y; then DO_UPGRADE=yes; else DO_UPGRADE=no; fi
  if ask_yn "Включить автоматические обновления безопасности?" y; then DO_AUTOUPD=yes; else DO_AUTOUPD=no; fi

  local cur tz
  cur=$(timedatectl show -p Timezone --value 2>/dev/null || echo "UTC")
  while true; do
    ask tz "Часовой пояс (Enter — оставить $cur; пример: Europe/Moscow)" ""
    if [[ -z $tz ]]; then TZ_NEW=""; break; fi
    if timedatectl list-timezones 2>/dev/null | grep -qxF "$tz"; then TZ_NEW=$tz; break; fi
    warn "Неизвестный часовой пояс (список: timedatectl list-timezones)"
  done

  if ask_yn "Применить безопасные sysctl-настройки сети (не трогают forwarding — VPN будут работать)?" y; then DO_SYSCTL=yes; else DO_SYSCTL=no; fi
  if ask_yn "Включить TCP BBR (ускоряет сеть на VPS/VPN, если ядро поддерживает)?" y; then DO_BBR=yes; else DO_BBR=no; fi

  if swapon --noheadings --show 2>/dev/null | grep -q .; then
    info "Swap уже настроен — пропускаю."
  else
    while true; do
      ask SWAP_GB "Размер swap в ГБ (0 — не создавать)" "0"
      [[ $SWAP_GB =~ ^[0-9]+$ ]] && (( SWAP_GB <= 64 )) && break
      warn "Целое число от 0 до 64"
    done
  fi
}

show_plan() {
  step "ИТОГОВЫЙ ПЛАН"
  echo "  Порт SSH:             $SSH_PORT"
  if [[ $CREATE_USER == yes ]]; then
    echo "  Пользователь:         $NEW_USER (sudo: $SUDO_MODE)"
  else
    echo "  Пользователь для ключа: $TARGET_USER"
  fi
  echo "  Новые ключи:          ${#NEW_KEYS[@]} шт.$( [[ $KEY_MODE == generate ]] && echo ' + будет сгенерирована пара на сервере')"
  echo "  Вход root по SSH:     $ROOT_LOGIN"
  echo "  Вход по паролю:       $( [[ $DISABLE_PW == yes ]] && echo 'ОТКЛЮЧЁН' || echo 'оставлен включённым')"
  echo "  SSH-лимиты:           MaxAuthTries=$MAX_AUTH LoginGraceTime=$LOGIN_GRACE MaxStartups=$MAX_STARTUPS"
  if [[ $DO_UFW == yes ]]; then
    echo "  UFW:                  включить; открыть ${SSH_PORT}/tcp ${EXTRA_PORTS[*]:-}"
  else
    echo "  UFW:                  не трогать"
  fi
  if [[ $DO_F2B == yes ]]; then
    echo "  Fail2Ban:             maxretry=$F2B_MAXRETRY bantime=$F2B_BANTIME findtime=$F2B_FINDTIME ignore=[${F2B_IGNORE:-—}]"
  else
    echo "  Fail2Ban:             нет"
  fi
  echo "  apt upgrade:          $DO_UPGRADE;  автообновления безопасности: $DO_AUTOUPD"
  echo "  Часовой пояс:         ${TZ_NEW:-не менять}"
  echo "  sysctl / BBR:         $DO_SYSCTL / $DO_BBR"
  echo "  Swap:                 $( (( SWAP_GB > 0 )) && echo "${SWAP_GB} ГБ" || echo 'нет')"
  echo
  warn "Текущее SSH-окно НЕ закрывайте до конца: проверка нового порта делается во втором окне."
  ask_yn "Применить настройки?" n || { info "Отменено, ничего не изменено."; exit 0; }
}

questionnaire() {
  detect_current_ssh_ports
  q_ssh_port
  q_user
  q_keys
  q_ssh_hardening
  q_firewall
  q_fail2ban
  q_system
  show_plan
}

# ----------------------------- выполнение ------------------------------------
do_packages() {
  step "Пакеты"
  mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
  info "apt update..."
  apt-get update -o DPkg::Lock::Timeout=180 -qq
  if [[ $DO_UPGRADE == yes ]]; then
    info "apt upgrade (может занять несколько минут)..."
    apt-get upgrade "${APT_OPTS[@]}" -qq
  fi
  local pkgs=(openssh-server curl ca-certificates sudo)
  [[ $DO_UFW == yes ]] && pkgs+=(ufw)
  [[ $DO_F2B == yes ]] && pkgs+=(fail2ban python3-systemd)
  [[ $DO_AUTOUPD == yes ]] && pkgs+=(unattended-upgrades)
  info "Установка: ${pkgs[*]}"
  apt-get install "${APT_OPTS[@]}" -qq "${pkgs[@]}"
  ok "Пакеты установлены"
}

do_autoupdates() {
  [[ $DO_AUTOUPD == yes ]] || return 0
  step "Автообновления безопасности"
  cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
  systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
  ok "unattended-upgrades включён (автоперезагрузки нет)"
}

do_timezone() {
  [[ -n $TZ_NEW ]] || return 0
  step "Часовой пояс"
  timedatectl set-timezone "$TZ_NEW"
  ok "Часовой пояс: $TZ_NEW"
}

do_user() {
  [[ $CREATE_USER == yes ]] || return 0
  step "Пользователь $NEW_USER"
  if ! user_exists "$NEW_USER"; then
    adduser --disabled-password --gecos "" "$NEW_USER"
    ok "Пользователь создан"
  fi
  usermod -aG sudo "$NEW_USER"

  if [[ $SUDO_MODE == nopasswd ]]; then
    local sf="/etc/sudoers.d/90-${NEW_USER}"
    printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$NEW_USER" >"$sf"
    chmod 440 "$sf"
    if ! visudo -cf "$sf" >/dev/null; then rm -f "$sf"; die "Ошибка в sudoers, файл удалён"; fi
    ok "sudo без пароля настроен"
  else
    local st
    st=$(passwd -S "$NEW_USER" 2>/dev/null | awk '{print $2}' || true)
    if [[ $st != P ]]; then
      info "Задайте пароль для $NEW_USER (нужен только для sudo; вход по SSH будет по ключу):"
      until passwd "$NEW_USER" </dev/tty; do warn "Не получилось, попробуйте ещё раз"; done
    fi
  fi
}

install_keys() {
  local u=$1 home grp ssh_dir f k
  home=$(user_home "$u")
  grp=$(id -gn "$u")
  ssh_dir="$home/.ssh"; f="$ssh_dir/authorized_keys"
  install -d -m 700 -o "$u" -g "$grp" "$ssh_dir"
  touch "$f"
  for k in "${NEW_KEYS[@]}"; do
    if ! grep -qxF -- "$k" "$f"; then printf '%s\n' "$k" >>"$f"; fi
  done
  chown "$u:$grp" "$f"
  chmod 600 "$f"
}

generate_server_key() {
  local d
  d=$(mktemp -d)
  ssh-keygen -q -t ed25519 -N "" -C "server-setup-$(date +%F)" -f "$d/key"
  NEW_KEYS+=("$(cat "$d/key.pub")")
  {
    echo
    echo "${C_BLD}=== ПРИВАТНЫЙ КЛЮЧ — скопируйте ЦЕЛИКОМ (с BEGIN/END) в файл на своём ПК ===${C_OFF}"
    echo "(например C:\\ssh_keys\\server_key, MobaXterm и ssh из Windows читают этот формат)"
    echo
    cat "$d/key"
    echo
    echo "После этого ключ будет безвозвратно удалён с сервера. Рекомендуется задать пароль на ключ: ssh-keygen -p -f <файл>"
  } >/dev/tty
  read -r -p "Нажмите Enter, когда сохранили ключ у себя... " _ </dev/tty || true
  shred -u "$d/key" 2>/dev/null || rm -f "$d/key"
  rm -rf "$d"
}

do_keys() {
  [[ $KEY_MODE != none ]] || return 0
  step "SSH-ключи"
  if [[ $KEY_MODE == generate ]]; then generate_server_key; fi
  install_keys "$TARGET_USER"
  ok "Ключи добавлены пользователю $TARGET_USER"
}

do_sysctl() {
  if [[ $DO_SYSCTL == yes ]]; then
    step "sysctl"
    cat >/etc/sysctl.d/99-server-hardening.conf <<'EOF'
# server-setup.sh: безопасные сетевые настройки (ip_forward и rp_filter не трогаем — для VPN)
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
kernel.dmesg_restrict = 1
EOF
  fi
  if [[ $DO_BBR == yes ]]; then
    modprobe tcp_bbr 2>/dev/null || true
    if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
      cat >/etc/sysctl.d/99-bbr.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
      ok "BBR включён"
    else
      warn "BBR недоступен в этом ядре — пропускаю"
    fi
  fi
  if [[ $DO_SYSCTL == yes || $DO_BBR == yes ]]; then
    sysctl --system >/dev/null 2>&1 || warn "Часть sysctl-параметров не применилась (норма для контейнеров)"
    ok "sysctl применён"
  fi
}

do_swap() {
  (( SWAP_GB > 0 )) || return 0
  step "Swap ${SWAP_GB} ГБ"
  if [[ -e /swapfile ]]; then warn "/swapfile уже существует — пропускаю"; return 0; fi
  local avail_gb
  avail_gb=$(( $(df --output=avail -k / | tail -1) / 1024 / 1024 ))
  if (( avail_gb < SWAP_GB + 2 )); then warn "Мало места на диске (${avail_gb} ГБ свободно) — swap пропущен"; return 0; fi
  if ! fallocate -l "${SWAP_GB}G" /swapfile 2>/dev/null; then
    dd if=/dev/zero of=/swapfile bs=1M count=$((SWAP_GB * 1024)) status=none
  fi
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null
  if swapon /swapfile 2>/dev/null; then
    grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >>/etc/fstab
    printf 'vm.swappiness = 10\n' >/etc/sysctl.d/99-swappiness.conf
    sysctl -p /etc/sysctl.d/99-swappiness.conf >/dev/null 2>&1 || true
    ok "Swap включён"
  else
    rm -f /swapfile
    warn "Не удалось включить swap (возможно, контейнер) — пропускаю"
  fi
}

do_ufw() {
  [[ $DO_UFW == yes ]] || return 0
  step "UFW"
  sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw 2>/dev/null || true
  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null
  ufw allow "${SSH_PORT}/tcp" comment 'SSH' >/dev/null
  local p
  for p in "${CUR_PORTS[@]}"; do
    if [[ $p != "$SSH_PORT" ]]; then ufw allow "${p}/tcp" comment 'SSH old (temporary)' >/dev/null; fi
  done
  for p in "${EXTRA_PORTS[@]}"; do
    ufw allow "$p" >/dev/null
  done
  ufw --force enable >/dev/null
  ok "UFW включён"
  ufw status | sed 's/^/    /'
}

close_old_ports() {
  [[ $DO_UFW == yes ]] || return 0
  local p
  info "Закрываю старые порты SSH в фаерволе..."
  for p in "${CUR_PORTS[@]}"; do
    if [[ $p == "$SSH_PORT" ]]; then continue; fi
    ufw --force delete allow "${p}/tcp" >/dev/null 2>&1 || true
    ufw --force delete allow "$p" >/dev/null 2>&1 || true
  done
  if [[ $SSH_PORT != 22 ]]; then ufw --force delete allow OpenSSH >/dev/null 2>&1 || true; fi
  ok "Старые порты закрыты"
}

rollback_ssh() {
  warn "Откатываю настройки SSH к прежним..."
  rm -f "$HARDENING_CONF"
  if [[ $SSH_BACKED_UP == yes && -d $BACKUP_DIR/ssh ]]; then
    cp -a "$BACKUP_DIR/ssh/." /etc/ssh/
    rm -f "$HARDENING_CONF"
  fi
  systemctl daemon-reload || true
  if ! systemctl restart ssh.service 2>/dev/null; then
    warn "ssh.service не стартует — возвращаю ssh.socket"
    systemctl unmask ssh.socket 2>/dev/null || true
    systemctl enable --now ssh.socket 2>/dev/null || true
  fi
  warn "SSH откатан. Правила UFW не менялись (старый и новый порты остаются открытыми)."
}

do_ssh() {
  step "Настройка SSH"
  mkdir -p /run/sshd "$BACKUP_DIR"
  chmod 700 "$BACKUP_DIR"
  cp -a /etc/ssh "$BACKUP_DIR/ssh"
  SSH_BACKED_UP=yes
  if [[ -f /etc/systemd/system/ssh.service.d/00-socket.conf ]]; then
    mkdir -p "$BACKUP_DIR/systemd"
    cp -a /etc/systemd/system/ssh.service.d "$BACKUP_DIR/systemd/"
  fi

  # Убираем посторонние Port (директива Port суммируется, а не переопределяется)
  local f
  for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
    if [[ -f $f && $f != "$HARDENING_CONF" ]]; then
      sed -i -E 's/^([[:space:]]*Port[[:space:]]+)/#\1/' "$f"
    fi
  done

  local pw="yes"
  [[ $DISABLE_PW == yes ]] && pw="no"

  # Имя 00-* читается раньше остальных drop-in (в sshd побеждает ПЕРВОЕ значение),
  # поэтому 50-cloud-init.conf с PasswordAuthentication yes нас не переопределит.
  cat >"$HARDENING_CONF" <<EOF
# Создано server-setup.sh v$SCRIPT_VERSION — $(date -Is)
Port $SSH_PORT
PermitRootLogin $ROOT_LOGIN
PasswordAuthentication $pw
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries $MAX_AUTH
LoginGraceTime $LOGIN_GRACE
MaxStartups $MAX_STARTUPS
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
  chmod 644 "$HARDENING_CONF"

  if ! sshd -t 2>/tmp/sshd-test.err; then
    err "Конфигурация SSH некорректна: $(cat /tmp/sshd-test.err)"
    rollback_ssh
    die "Остановлено, SSH не изменён."
  fi

  # Проверяем, что именно наши значения «победили» в итоговой конфигурации
  local eff
  eff=$(sshd -T 2>/dev/null)
  local nports root_re="$ROOT_LOGIN"
  nports=$(grep -c '^port ' <<<"$eff" || true)
  # sshd -T выводит prohibit-password под старым именем without-password
  if [[ $ROOT_LOGIN == prohibit-password ]]; then root_re="(prohibit-password|without-password)"; fi
  if ! grep -qx "port $SSH_PORT" <<<"$eff" || [[ $nports != 1 ]] \
     || ! grep -qx "passwordauthentication $pw" <<<"$eff" \
     || ! grep -Eqx "permitrootlogin $root_re" <<<"$eff"; then
    err "Итоговая конфигурация sshd отличается от задуманной:"
    grep -E '^(port|passwordauthentication|permitrootlogin) ' <<<"$eff" | sed 's/^/    /' >&2
    rollback_ssh
    die "Остановлено, SSH не изменён."
  fi
  ok "Конфигурация проверена (sshd -t, sshd -T)"

  # Ubuntu 24.04: socket activation → переходим на классическую службу
  systemctl disable --now ssh.socket 2>/dev/null || true
  rm -f /etc/systemd/system/ssh.service.d/00-socket.conf
  systemctl daemon-reload
  systemctl unmask ssh.service 2>/dev/null || true
  systemctl enable ssh.service 2>/dev/null || true
  if ! systemctl restart ssh.service; then
    rollback_ssh
    die "Не удалось перезапустить ssh.service"
  fi

  local listening=no i
  for i in {1..15}; do
    if ss -Htln "sport = :$SSH_PORT" | grep -q .; then listening=yes; break; fi
    sleep 1
  done
  if [[ $listening != yes ]]; then
    rollback_ssh
    die "SSH не слушает порт $SSH_PORT — изменения откатаны."
  fi
  # маскируем сокет, чтобы ничто не включило его обратно
  systemctl mask ssh.socket 2>/dev/null || true
  ok "SSH слушает порт $SSH_PORT (служба ssh.service, сокет отключён)"
}

confirm_new_ssh() {
  local ip
  ip=$(server_ip)
  echo
  echo "${C_BLD}ПРОВЕРКА ПОДКЛЮЧЕНИЯ — не закрывайте это окно!${C_OFF}"
  echo "Откройте НОВОЕ окно терминала / MobaXterm и подключитесь:"
  echo
  echo "    ssh -p $SSH_PORT ${TARGET_USER}@${ip}"
  echo "    (с ключом: ssh -i путь/к/ключу -p $SSH_PORT ${TARGET_USER}@${ip})"
  echo
  echo "В MobaXterm: порт $SSH_PORT, пользователь $TARGET_USER, Use private key."
  if [[ $ROOT_LOGIN == no ]]; then echo "Вход root теперь запрещён — заходите под $TARGET_USER."; fi
  echo
  ask_yn "Вход в новом окне удался?" n
}

do_fail2ban() {
  [[ $DO_F2B == yes ]] || return 0
  step "Fail2Ban"
  if [[ -f /etc/fail2ban/jail.local ]]; then
    mkdir -p "$BACKUP_DIR"; cp -a /etc/fail2ban/jail.local "$BACKUP_DIR/jail.local"
  fi
  cat >/etc/fail2ban/jail.local <<EOF
# Создано server-setup.sh v$SCRIPT_VERSION
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 ${F2B_IGNORE}
bantime  = ${F2B_BANTIME}
findtime = ${F2B_FINDTIME}
maxretry = ${F2B_MAXRETRY}
# повторные нарушители банятся на всё более долгий срок
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 4w

[sshd]
enabled = true
port    = ${SSH_PORT}
filter  = sshd
backend = systemd
EOF
  systemctl enable fail2ban >/dev/null 2>&1
  systemctl restart fail2ban
  local i ok_f2b=no
  for i in {1..10}; do
    if fail2ban-client status sshd >/dev/null 2>&1; then ok_f2b=yes; break; fi
    sleep 1
  done
  if [[ $ok_f2b == yes ]]; then
    ok "Fail2Ban работает, jail sshd активен"
  else
    warn "Fail2Ban запущен, но jail sshd не отвечает. Проверьте: journalctl -u fail2ban -n 50"
  fi
}

write_summary() {
  local ip
  ip=$(server_ip)
  cat >"$SUMMARY_FILE" <<EOF
server-setup.sh v$SCRIPT_VERSION — $(date -Is)
Порт SSH:        $SSH_PORT
Пользователь:    $TARGET_USER
Вход root:       $ROOT_LOGIN
Пароли SSH:      $( [[ $DISABLE_PW == yes ]] && echo отключены || echo включены )
Подключение:     ssh -p $SSH_PORT ${TARGET_USER}@${ip}
Бэкапы:          $BACKUP_DIR
Конфиг SSH:      $HARDENING_CONF
Конфиг Fail2Ban: /etc/fail2ban/jail.local

Полезные команды:
  sudo fail2ban-client status sshd
  sudo fail2ban-client set sshd unbanip <IP>
  sudo ufw status verbose
  sudo ufw allow <порт>/tcp
  sudo ss -tulpn
EOF
  chmod 600 "$SUMMARY_FILE"
}

finish() {
  write_summary
  local ip
  ip=$(server_ip)
  step "ГОТОВО"
  ok "Базовая защита применена."
  echo
  echo "  Подключение:  ssh -p $SSH_PORT ${TARGET_USER}@${ip}"
  echo "  Памятка:      $SUMMARY_FILE"
  echo "  Бэкапы:       $BACKUP_DIR"
  echo
  echo "  Бан-статус:   sudo fail2ban-client status sshd"
  echo "  Разбанить:    sudo fail2ban-client set sshd unbanip <IP>"
  echo "  Открыть порт: sudo ufw allow <порт>/tcp   (для новых сервисов/VPN)"
  echo
  if [[ $DO_UFW == yes ]]; then
    warn "Docker публикует порты в обход UFW. Для контейнеров привязывайте порты к 127.0.0.1 или управляйте правилами в цепочке DOCKER-USER."
  fi
  if [[ -f /var/run/reboot-required ]]; then
    warn "Нужна перезагрузка (обновилось ядро/библиотеки): sudo reboot"
  fi
}

execute() {
  do_packages
  do_autoupdates
  do_timezone
  do_user
  do_keys
  do_sysctl
  do_swap
  do_ufw
  do_ssh
  if ! confirm_new_ssh; then
    rollback_ssh
    die "Вход по новому порту не подтверждён — SSH возвращён к прежним настройкам. Запустите скрипт снова после выяснения причины."
  fi
  close_old_ports
  do_fail2ban
  finish
}

main() {
  case ${1:-} in -h|--help) usage; exit 0 ;; esac
  printf '%sserver-setup.sh v%s — защита чистого VPS (Ubuntu 24.04)%s\n' "$C_BLD" "$SCRIPT_VERSION" "$C_OFF"
  preflight
  questionnaire
  execute
}

# main вызывается последней строкой: при обрыве загрузки неполный скрипт не выполнится
if [[ -z ${BASH_SOURCE[0]:-} || ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
