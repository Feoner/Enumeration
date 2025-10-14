#!/usr/bin/env bash
set -e

# If the first arg looks like an option, pass it to the script
if [[ "${1#-}" != "$1" || "$1" == "-h" || "$1" == "--help" ]]; then
  exec /usr/local/bin/lazyrecon-plus.sh "$@"
fi

# Otherwise treat remaining as script args (e.g. -d example.com)
exec /usr/local/bin/lazyrecon-plus.sh "$@"
