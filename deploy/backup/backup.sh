#!/bin/sh
# Backs up the SereS database every BACKUP_DAYS days (default 7) into
# /backups and keeps the newest BACKUP_KEEP (default 4). The database holds
# everything: accounts, chats, profile pictures and attachments.
#
#   backup.sh        keep running and back up when the last backup is due
#   backup.sh now    back up once right away
set -eu
umask 077

DB="${BACKUP_DB:-/data/users.db}"
DIR="${BACKUP_DIR:-/backups}"
DAYS="${BACKUP_DAYS:-7}"
KEEP="${BACKUP_KEEP:-4}"

require_positive_int() {
  case "$2" in
    ''|*[!0-9]*)
      echo "$1 must be a positive integer (>= 1), got: $2" >&2
      exit 1
      ;;
  esac
  if [ "$2" -lt 1 ]; then
    echo "$1 must be a positive integer (>= 1), got: $2" >&2
    exit 1
  fi
}

require_positive_int BACKUP_DAYS "$DAYS"
require_positive_int BACKUP_KEEP "$KEEP"

CURRENT_TMP=""
SLEEP_PID=""
STOP=0

cleanup() {
  if [ -n "${CURRENT_TMP:-}" ]; then
    rm -f "$CURRENT_TMP" "${CURRENT_TMP}.gz"
    CURRENT_TMP=""
  fi
}

on_signal() {
  STOP=1
  if [ -n "${SLEEP_PID:-}" ]; then
    kill "$SLEEP_PID" 2>/dev/null || true
  fi
  cleanup
  exit 0
}

trap cleanup EXIT
trap on_signal INT TERM HUP

backup() {
  if [ ! -f "$DB" ]; then
    echo "No database at $DB yet, nothing to back up."
    return 0
  fi
  stamp="$(date +%Y-%m-%d_%H%M)"
  CURRENT_TMP="$(mktemp "$DIR/.users-$stamp.XXXXXX")"
  # .backup makes a consistent copy while SereS keeps running.
  sqlite3 -cmd ".timeout 15000" "$DB" ".backup '$CURRENT_TMP'"
  if [ "$(sqlite3 -cmd ".timeout 15000" "$CURRENT_TMP" 'PRAGMA integrity_check;')" != "ok" ]; then
    rm -f "$CURRENT_TMP"
    CURRENT_TMP=""
    echo "Backup failed the integrity check, kept the older backups." >&2
    return 1
  fi
  gzip -f "$CURRENT_TMP"
  chmod 600 "${CURRENT_TMP}.gz"
  mv "${CURRENT_TMP}.gz" "$DIR/users-$stamp.db.gz"
  chmod 600 "$DIR/users-$stamp.db.gz"
  CURRENT_TMP=""
  echo "Backup saved: users-$stamp.db.gz ($(du -h "$DIR/users-$stamp.db.gz" | cut -f1))"
  # Only the newest $KEEP backups stay.
  ls -1t "$DIR"/users-*.db.gz | tail -n +"$((KEEP + 1))" | while read -r old; do
    rm -f "$old" && echo "Removed old backup: ${old##*/}"
  done
}

if ! touch "$DIR/.write-test" 2>/dev/null; then
  echo "Can't write to $DIR. Create the folder as the SereS user: mkdir -p backups" >&2
  exit 1
fi
rm -f "$DIR/.write-test"

if [ "${1:-}" = "now" ]; then
  backup
  exit
fi

echo "Backing up every $DAYS days, keeping $KEEP backups."
while [ "$STOP" -eq 0 ]; do
  newest="$(ls -1t "$DIR"/users-*.db.gz 2>/dev/null | head -n 1 || true)"
  # Due when there is no backup yet or the newest is at least $DAYS days old.
  if [ -z "$newest" ] || [ -n "$(find "$newest" -mtime +"$((DAYS - 1))")" ]; then
    backup || true
  fi
  sleep 3600 &
  SLEEP_PID=$!
  wait "$SLEEP_PID" || true
  SLEEP_PID=""
done
