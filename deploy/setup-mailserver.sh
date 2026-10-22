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
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --hostname) MAIL_HOSTNAME="${2:-}"; shift 2 ;;
    --from) FROM="${2:-}"; shift 2 ;;
    --public-url) PUBLIC_URL="${2:-}"; shift 2 ;;
    --seres-env) SERES_ENV="${2:-}"; shift 2 ;;
    --ip) SERVER_IP="${2:-}"; shift 2 ;;
    --test-to) TEST_TO="${2:-}"; shift 2 ;;
    -h | --help) usage 0 ;;
    *) echo "Unknown option: $1" >&2; usage 1 ;;
  esac
done

# ---------------------------------------------------------------- checks

[[ $EUID -eq 0 ]] || die "Please run as root (sudo $0 ...)."
[[ -n "$DOMAIN" ]] || die "--domain is required, e.g. --domain example.com"
[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "'$DOMAIN' is not a valid domain."
if ! grep -qi ubuntu /etc/os-release 2>/dev/null; then
  echo "Warning: this script was written for Ubuntu; continuing anyway." >&2
fi

MAIL_HOSTNAME="${MAIL_HOSTNAME:-mail.$DOMAIN}"
FROM="${FROM:-no-reply@$DOMAIN}"
[[ "$FROM" == *"@$DOMAIN" ]] || die "--from must be an address @$DOMAIN (DKIM signs only this domain)."

if [[ -z "$SERVER_IP" ]]; then
  SERVER_IP="$(curl -4 -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  [[ -n "$SERVER_IP" ]] || SERVER_IP="$(hostname -I | awk '{print $1}')"
fi

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

set_env() {
  local file="$1" key="$2" value="$3"
  touch "$file"
  # Replace an existing line or append a new one.
  if grep -q "^$key=" "$file"; then
    sed -i "s|^$key=.*|$key=$value|" "$file"
  else
    # Without this, the new line would be glued to a last line that has no
    # line break (as in the .env of the repository).
    [[ -s "$file" && -n "$(tail -c 1 "$file")" ]] && echo >>"$file"
    printf '%s=%s\n' "$key" "$value" >>"$file"
  fi
}

if [[ -n "$SERES_ENV" ]]; then
  echo "==> Writing SMTP settings to $SERES_ENV"
  set_env "$SERES_ENV" SMTP_HOST localhost
  set_env "$SERES_ENV" SMTP_PORT 25
  set_env "$SERES_ENV" SMTP_SECURITY none
  set_env "$SERES_ENV" MAIL_FROM "\"SereS <$FROM>\""
  [[ -n "$PUBLIC_URL" ]] && set_env "$SERES_ENV" PUBLIC_URL "$PUBLIC_URL"
  chmod 600 "$SERES_ENV"
  echo "    Restart SereS so it reads the new settings."
fi

# ------------------------------------------------------------- test mail

if [[ -n "$TEST_TO" ]]; then
  echo "==> Sending a test mail to $TEST_TO"
  printf 'This is a test mail from the SereS mail server on %s.\n' "$MAIL_HOSTNAME" |
    mail -s "SereS test mail" -r "$FROM" "$TEST_TO"
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
