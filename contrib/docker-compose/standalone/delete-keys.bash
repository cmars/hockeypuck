#!/bin/bash

# Delete keys from the Hockeypuck postgres database by fingerprint

set -euo pipefail

if [[ ! ${1:-} ]]; then
    cat <<EOF
Usage: $0 FINGERPRINT [FINGERPRINT ...]
EOF
    exit 1
fi

# Uncomment and edit one of the below for your postgres installation
# for docker-compose/standalone default configuration
SQLCMD="docker exec -i standalone_postgres_1 psql hkp -U hkp"
# for docker-compose/dev default configuration
#SQLCMD="docker exec -i hockeypuck_postgres_1 psql hkp -U docker"
# for non-docker postgres, e.g.
#SQLCMD="psql hkp -U hkp"

reverse_fp() {
  # print the input string in reverse order
  input=$1
  while [[ $input ]]; do
    echo -n "${input: -1}"
    input="${input%?}"
  done
  echo
}

reverse_fplist() {
  local rfplist
  for fp in "$@"; do
    rfp=$(reverse_fp "${fp,,}") # fold to lowercase and reverse
    if [[ ${rfplist:-} ]]; then
        rfplist="$rfplist, '$rfp'"
    else
        rfplist="'$rfp'"
    fi
  done
  echo "$rfplist"
}

rfplist=$(reverse_fplist "$@")
$SQLCMD <<EOF
delete from subkeys where rfingerprint in (${rfplist});
delete from keys where rfingerprint in (${rfplist});
EOF
