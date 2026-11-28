#!/usr/bin/env bash
# Sets up a send-only mail server for SereS on Ubuntu (22.04 / 24.04).
#
#   - Postfix that only listens on localhost (no open ports, no open relay)
#   - OpenDKIM signs every mail, so Gmail & co. accept it
#   - prints the DNS records you have to create (SPF, DKIM, DMARC, PTR)
#   - optionally writes the SMTP settings into SereS' .env
#
# SereS only *sends* mails (password reset links), so no mailboxes, IMAP or
# spam filter are needed. Replies to no-reply@ are not received.
#
# Usage:
#   sudo ./setup-mailserver.sh --domain example.com \
#        [--hostname mail.example.com] [--from no-reply@example.com] \
#        [--public-url https://chat.example.com] \
#        [--seres-env /opt/SereS/src/backend/.env] \
#        [--ip 203.0.113.10] [--test-to you@example.org]
#
# Run it again at any time: it keeps the existing DKIM key.

set -euo pipefail

DOMAIN=""
MAIL_HOSTNAME=""
FROM=""
PUBLIC_URL=""
SERES_ENV=""
SERVER_IP=""
TEST_TO=""
SELECTOR="seres"

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) [[ $# -ge 2 ]] || die "--domain requires a value"; DOMAIN="$2"; shift 2 ;;
    --hostname) [[ $# -ge 2 ]] || die "--hostname requires a value"; MAIL_HOSTNAME="$2"; shift 2 ;;
    --from) [[ $# -ge 2 ]] || die "--from requires a value"; FROM="$2"; shift 2 ;;
    --public-url) [[ $# -ge 2 ]] || die "--public-url requires a value"; PUBLIC_URL="$2"; shift 2 ;;
    --seres-env) [[ $# -ge 2 ]] || die "--seres-env requires a value"; SERES_ENV="$2"; shift 2 ;;
    --ip) [[ $# -ge 2 ]] || die "--ip requires a value"; SERVER_IP="$2"; shift 2 ;;
    --test-to) [[ $# -ge 2 ]] || die "--test-to requires a value"; TEST_TO="$2"; shift 2 ;;
    -h | --help) usage 0 ;;
    *) echo "Unknown option: $1" >&2; usage 1 ;;
  esac
done

has_ctrl() {
  [[ "$1" == *$'\n'* || "$1" == *$'\r'* || "$1" =~ [[:cntrl:]] ]]
}

valid_domain() {
  local d="$1"
  ! has_ctrl "$d" && [[ ${#d} -le 253 && "$d" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}

valid_email() {
  local e="$1"
  ! has_ctrl "$e" && [[ ${#e} -le 254 && "$e" =~ ^[A-Za-z0-9._%+-]+@([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}

valid_ipv4() {
  local ip="$1" o
  ! has_ctrl "$ip" || return 1
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local IFS='.'
  read -r -a octets <<<"$ip"
  [[ ${#octets[@]} -eq 4 ]] || return 1
  for o in "${octets[@]}"; do
    [[ "$o" == "0" || ! "$o" =~ ^0 ]] || return 1
    ((10#$o >= 0 && 10#$o <= 255)) || return 1
  done
}

valid_public_url() {
  local u="$1"
  ! has_ctrl "$u" || return 1
  [[ "$u" != *"@"* ]] || return 1
  [[ "$u" =~ ^https://([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(:[0-9]{1,5})?(/[^\s\"\'\<\>\\]*)?$ ]]
}

# ---------------------------------------------------------------- checks

[[ $EUID -eq 0 ]] || die "Please run as root (sudo $0 ...)."
[[ -n "$DOMAIN" ]] || die "--domain is required, e.g. --domain example.com"
valid_domain "$DOMAIN" || die "'$DOMAIN' is not a valid domain."
if ! grep -qi ubuntu /etc/os-release 2>/dev/null; then
  echo "Warning: this script was written for Ubuntu; continuing anyway." >&2
fi

MAIL_HOSTNAME="${MAIL_HOSTNAME:-mail.$DOMAIN}"
valid_domain "$MAIL_HOSTNAME" || die "'$MAIL_HOSTNAME' is not a valid mail hostname."
FROM="${FROM:-no-reply@$DOMAIN}"
valid_email "$FROM" || die "'$FROM' is not a valid sender email address."
[[ "$FROM" == *"@$DOMAIN" ]] || die "--from must be an address @$DOMAIN (DKIM signs only this domain)."
if [[ -n "$PUBLIC_URL" ]]; then
  valid_public_url "$PUBLIC_URL" || die "'$PUBLIC_URL' is not a valid https:// URL."
fi
if [[ -n "$TEST_TO" ]]; then
  valid_email "$TEST_TO" || die "'$TEST_TO' is not a valid recipient email address."
fi
if [[ -n "$SERES_ENV" ]]; then
  ! has_ctrl "$SERES_ENV" || die "Invalid --seres-env path."
  [[ -d "$(dirname "$SERES_ENV")" ]] || die "Parent directory for --seres-env does not exist: $(dirname "$SERES_ENV")"
fi

if [[ -z "$SERVER_IP" ]]; then
  SERVER_IP="$(curl -4 -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  [[ -n "$SERVER_IP" ]] || SERVER_IP="$(hostname -I | awk '{print $1}')"
fi
valid_ipv4 "$SERVER_IP" || die "'$SERVER_IP' is not a valid IPv4 address."

echo "==> Domain:        $DOMAIN"
echo "==> Mail hostname: $MAIL_HOSTNAME"
echo "==> Sender:        $FROM"
echo "==> Server IPv4:   $SERVER_IP"

# --------------------------------------------------------------- packages

echo "==> Installing Postfix and OpenDKIM"
export DEBIAN_FRONTEND=noninteractive
echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
echo "postfix postfix/mailname string $DOMAIN" | debconf-set-selections
apt-get update -qq
apt-get install -y -qq postfix opendkim opendkim-tools ca-certificates bsd-mailx curl >/dev/null

echo "$DOMAIN" >/etc/mailname

# ---------------------------------------------------------------- postfix

echo "==> Configuring Postfix (send-only, localhost)"
postconf -e \
  "myhostname = $MAIL_HOSTNAME" \
  "mydomain = $DOMAIN" \
  "myorigin = /etc/mailname" \
  "inet_interfaces = loopback-only" \
  "inet_protocols = ipv4" \
  "mydestination = localhost" \
  "mynetworks = 127.0.0.0/8" \
  "relayhost =" \
  "smtpd_relay_restrictions = permit_mynetworks, reject" \
  "smtp_tls_security_level = may" \
  "smtp_tls_CApath = /etc/ssl/certs" \
  "smtp_tls_loglevel = 1" \
  "smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache" \
  "smtpd_banner = \$myhostname ESMTP" \
  "disable_vrfy_command = yes" \
  "message_size_limit = 10240000" \
  "milter_default_action = accept" \
  "milter_protocol = 6" \
  "smtpd_milters = inet:127.0.0.1:8891" \
  "non_smtpd_milters = inet:127.0.0.1:8891"

# ---------------------------------------------------------------- opendkim

echo "==> Configuring OpenDKIM"
KEY_DIR="/etc/opendkim/keys/$DOMAIN"
mkdir -p "$KEY_DIR"
if [[ ! -f "$KEY_DIR/$SELECTOR.private" ]]; then
  opendkim-genkey -b 2048 -d "$DOMAIN" -D "$KEY_DIR" -s "$SELECTOR" -v
else
  echo "    keeping the existing DKIM key $KEY_DIR/$SELECTOR.private"
fi
chown -R opendkim:opendkim /etc/opendkim
chmod 700 "$KEY_DIR"
chmod 600 "$KEY_DIR/$SELECTOR.private"

cat >/etc/opendkim.conf <<EOF
# Written by SereS deploy/setup-mailserver.sh
Syslog                  yes
UMask                   007
Mode                    s
Domain                  $DOMAIN
Selector                $SELECTOR
KeyFile                 $KEY_DIR/$SELECTOR.private
Canonicalization        relaxed/simple
OversignHeaders         From
Socket                  inet:8891@127.0.0.1
UserID                  opendkim
EOF

# Ubuntu's service reads the socket from /etc/default/opendkim (it overrides the
# config file), so set it there as well and regenerate the systemd override.
if [[ -f /etc/default/opendkim ]]; then
  if grep -q '^SOCKET=' /etc/default/opendkim; then
    sed -i 's|^SOCKET=.*|SOCKET=inet:8891@127.0.0.1|' /etc/default/opendkim
  else
    echo 'SOCKET=inet:8891@127.0.0.1' >>/etc/default/opendkim
  fi
fi
if [[ -x /lib/opendkim/opendkim.service.generate ]]; then
  /lib/opendkim/opendkim.service.generate
  systemctl daemon-reload
fi

systemctl enable --now opendkim >/dev/null
systemctl restart opendkim
systemctl enable --now postfix >/dev/null
systemctl restart postfix

# ------------------------------------------------------------ SereS .env

env_owner() {
  local file="$1" dir owner uid
  dir="$(dirname "$file")"
  owner="$(stat -c '%u:%g' "$dir" 2>/dev/null || true)"
  uid="${owner%%:*}"
  if [[ -n "$owner" && "$uid" != "0" ]]; then
    printf '%s\n' "$owner"
    return 0
  fi
  if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    printf '%s:%s\n' "$(id -u "$SUDO_USER")" "$(id -g "$SUDO_USER")"
    return 0
  fi
  if [[ -e "$file" ]]; then
    stat -c '%u:%g' "$file" 2>/dev/null || true
  fi
}

set_env() {
  local file="$1" key="$2" value="$3" dir tmp="" owner
  dir="$(dirname "$file")"
  tmp="$(mktemp "$dir/.seres-env.XXXXXX")"
  trap 'rm -f "$tmp"' RETURN
  if [[ -f "$file" ]]; then
    SERES_ENV_KEY="$key" SERES_ENV_VAL="$value" awk '
      BEGIN {
        k = ENVIRON["SERES_ENV_KEY"]
        v = ENVIRON["SERES_ENV_VAL"]
        prefix = k "="
        plen = length(prefix)
        found = 0
      }
      substr($0, 1, plen) == prefix {
        if (!found) {
          print k "=" v
          found = 1
        }
        next
      }
      { print }
      END {
        if (!found) print k "=" v
      }
    ' "$file" >"$tmp"
  else
    printf '%s=%s\n' "$key" "$value" >"$tmp"
  fi
  owner="$(env_owner "$file")"
  [[ -n "$owner" ]] && chown "$owner" "$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$file"
  trap - RETURN
}

remove_env() {
  local file="$1" key="$2" dir tmp="" owner
  [[ -f "$file" ]] || return 0
  dir="$(dirname "$file")"
  tmp="$(mktemp "$dir/.seres-env.XXXXXX")"
  trap 'rm -f "$tmp"' RETURN
  SERES_ENV_KEY="$key" awk '
    BEGIN {
      prefix = ENVIRON["SERES_ENV_KEY"] "="
      plen = length(prefix)
    }
    substr($0, 1, plen) == prefix { next }
    { print }
  ' "$file" >"$tmp"
  owner="$(env_owner "$file")"
  [[ -n "$owner" ]] && chown "$owner" "$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$file"
  trap - RETURN
}

if [[ -n "$SERES_ENV" ]]; then
  echo "==> Writing SMTP settings to $SERES_ENV"
  set_env "$SERES_ENV" SMTP_HOST localhost
  set_env "$SERES_ENV" SMTP_PORT 25
  set_env "$SERES_ENV" SMTP_SECURITY none
  remove_env "$SERES_ENV" SMTP_USER
  remove_env "$SERES_ENV" SMTP_PASSWORD
  set_env "$SERES_ENV" MAIL_FROM "\"SereS <$FROM>\""
  [[ -n "$PUBLIC_URL" ]] && set_env "$SERES_ENV" PUBLIC_URL "$PUBLIC_URL"
  owner="$(env_owner "$SERES_ENV")"
  [[ -n "$owner" ]] && chown "$owner" "$SERES_ENV"
  chmod 600 "$SERES_ENV"
  echo "    Restart SereS so it reads the new settings."
fi

# ------------------------------------------------------------- test mail

if [[ -n "$TEST_TO" ]]; then
  echo "==> Sending a test mail to $TEST_TO"
  printf 'This is a test mail from the SereS mail server on %s.\n' "$MAIL_HOSTNAME" |
    mail -s "SereS test mail" -r "$FROM" -- "$TEST_TO"
  echo "    Check the inbox (and spam folder). Logs: journalctl -u postfix -n 50"
fi

# ------------------------------------------------------------ DNS records

DKIM_VALUE="$(sed -e 's/^[^"]*"//' -e 's/"[^"]*$//' -e 's/"[[:space:]]*"//g' "$KEY_DIR/$SELECTOR.txt" | tr -d '\n\t ' | sed 's/;/; /g')"

cat <<EOF

================================================================================
 Done. Now create these DNS records at your domain provider:
================================================================================

EOF
printf ' %-5s %-36s %s\n' "Type" "Name" "Value"
printf ' %-5s %-36s %s\n' "A" "$MAIL_HOSTNAME." "$SERVER_IP"
printf ' %-5s %-36s %s\n' "TXT" "$DOMAIN." "v=spf1 ip4:$SERVER_IP -all"
printf ' %-5s %-36s %s\n' "TXT" "$SELECTOR._domainkey.$DOMAIN." "$DKIM_VALUE"
printf ' %-5s %-36s %s\n' "TXT" "_dmarc.$DOMAIN." "v=DMARC1; p=quarantine; adkim=s; aspf=s"
cat <<EOF

 PTR (reverse DNS): set it for $SERVER_IP to $MAIL_HOSTNAME
 in the control panel of your server hoster (not at the domain provider).

 If the domain already has an SPF record, add "ip4:$SERVER_IP" to it instead
 of creating a second one.

 Notes:
 - Many hosters block outgoing port 25 by default; ask them to unblock it
   (Hetzner, OVH, DigitalOcean, ... have a form for that).
 - Check the setup after the DNS changes with https://www.mail-tester.com
 - SereS settings (if you didn't use --seres-env), in src/backend/.env:
     SMTP_HOST=localhost
     SMTP_PORT=25
     SMTP_SECURITY=none
     MAIL_FROM="SereS <$FROM>"
     PUBLIC_URL=https://your-seres-domain
================================================================================
EOF
