#!/usr/bin/env bash
# Full wipe: remove every trace of previous runs.
#
# RESET_ON_START=true already clears scan artefacts on each boot, but three
# things survive it because they live outside the application's control:
#
#   postgres-data   named docker volume - survives `docker compose down`
#   redis-data      named docker volume - survives `docker compose down`
#   ./data          BIND MOUNT - survives even `docker compose down -v`
#
# That last one is the surprising one, and it is why a "from scratch" restart
# still felt like it remembered things. This script deals with all three.
#
# Usage:
#   ./wipe.sh            interactive, asks before deleting
#   ./wipe.sh --yes      no prompt
#   ./wipe.sh --keep-ca  keep the mitmproxy CA (clients stay trusted)
set -euo pipefail

cd "$(dirname "$0")"

ASSUME_YES=0
KEEP_CA=0
for arg in "$@"; do
  case "$arg" in
    --yes|-y)   ASSUME_YES=1 ;;
    --keep-ca)  KEEP_CA=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

echo "This deletes:"
echo "  - the postgres volume (engagements, findings, jobs, audit log,"
echo "    AND THE OPERATOR ACCOUNT - the next start will ask you to create"
echo "    one again, which is the setup page, not a broken install)"
echo "  - the redis volume (queued jobs)"
if [ "$KEEP_CA" -eq 1 ]; then
  echo "  - ./data EXCEPT the mitmproxy CA and the settings key"
else
  echo "  - ./data in full, INCLUDING the mitmproxy CA and the settings key"
  echo "    (a new CA means every client you configured must trust the new one,"
  echo "     and stored provider API keys become undecryptable)"
fi
echo

if [ "$ASSUME_YES" -ne 1 ]; then
  read -r -p "Proceed? [y/N] " reply
  case "$reply" in [yY]*) ;; *) echo "aborted"; exit 1 ;; esac
fi

echo "==> stopping the stack and removing volumes"
docker compose down -v --remove-orphans

echo "==> clearing ./data"
if [ -d data ]; then
  if [ "$KEEP_CA" -eq 1 ]; then
    find data -mindepth 1 -maxdepth 1 \
      ! -name '.settings.key' ! -name 'mitmproxy' -exec rm -rf {} +
  else
    rm -rf data
    mkdir -p data
  fi
fi

echo
echo
echo "Done. Nothing from the previous runs remains."
echo "Bring it back up with: docker compose up -d --build"
echo "Then create the operator account again, and reconnect a model."
