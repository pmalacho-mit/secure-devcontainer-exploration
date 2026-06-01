
SWEATER_VEST_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
node --import tsx "$SWEATER_VEST_DIR/report/index.ts" "$@"