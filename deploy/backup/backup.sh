#!/bin/sh
# Backs up the SereS database every BACKUP_DAYS days (default 7) into
# /backups and keeps the newest BACKUP_KEEP (default 4). The database holds
# everything: accounts, chats, profile pictures and attachments.
#
#   backup.sh        keep running and back up when the last backup is due
#   backup.sh now    back up once right away
set -eu

DB=/data/users.db
DIR=/backups
DAYS="${BACKUP_DAYS:-7}"
KEEP="${BACKUP_KEEP:-4}"

backup() {
  if [ ! -f "$DB" ]; then
    echo "No database at $DB yet, nothing to back up."
    return 0
  fi
  stamp="$(date +%Y-%m-%d_%H%M)"
  tmp="$DIR/.users-$stamp.db"
  # .backup makes a consistent copy while SereS keeps running.
  sqlite3 "$DB" ".backup '$tmp'"
  if [ "$(sqlite3 "$tmp" 'PRAGMA integrity_check;')" != "ok" ]; then
    rm -f "$tmp"
    echo "Backup failed the integrity check, kept the older backups." >&2
    return 1
  fi
  gzip -f "$tmp"
  mv "$tmp.gz" "$DIR/users-$stamp.db.gz"
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
while true; do
  newest="$(ls -1t "$DIR"/users-*.db.gz 2>/dev/null | head -n 1 || true)"
  # Due when there is no backup yet or the newest is at least $DAYS days old.
  if [ -z "$newest" ] || [ -n "$(find "$newest" -mtime +"$((DAYS - 1))")" ]; then
    backup || true
  fi
  sleep 3600
done
