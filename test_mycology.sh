#!/bin/bash

# shell coloring
CYAN='\e[0;36m'
YELLOW='\e[0;33m'
RED='\e[0;31m'
RESET='\e[0m'

PROMPT="${CYAN}$(basename "$0"):${RESET}"

# other constants
COMPILER="compiler.py"
MYCOLOGY_USER="Deewiant"
MYCOLOGY_NAME="Mycology"
MYCOLOGY_GITHUB="https://github.com/$MYCOLOGY_USER/$MYCOLOGY_NAME.git"

function log_ok {
  echo -e "$PROMPT" "$@"
}

function prompt {
  echo -ne "$PROMPT" "$@"
}

function log_err {
  echo -e "$PROMPT" "${RED}Error:${RESET}" "$@"
}

function log_warn {
  echo -e "$PROMPT" "${YELLOW}Warning:${RESET}" "$@"
}

# check if a file exists and if so ask to overwrite it
# exit if user asks not to
function check_file {
  if [ -e "$1" ]; then
    prompt "overwrite \`$1\`? (y/n): "
    read -r overwrite
    if [ "$overwrite" != "y" ]; then
      log_err "Cannot continue execution"
      exit 1
    fi
  fi
}

function expect_file {
  if [ ! -e "$1" ]; then
    log_err "Could not find \`$1\`"
    exit 1
  fi
}

function ensure_mycology_exists {
  if [ ! -d Mycology ]; then
    log_ok "Downloading Mycology..."
    if ! git clone "$MYCOLOGY_GITHUB"; then
      log_err "Failed to download Mycology"
      exit 1
    fi
  fi
}

function test {
  FILE="$1"
  if [ $# -gt 1 ]; then
    TIMEOUT_TIME="$2"
  else
    TIMEOUT_TIME="0s"
  fi
  
  log_ok "Testing \`$(basename "$FILE")\`..."
  expect_file "$FILE"

  ASM_FILE="${FILE%.*}.s"
  EXE_FILE="${FILE%.*}"
  
  check_file "$ASM_FILE"
  check_file "$EXE_FILE"

  log_ok "Compiling..."

  if ! ./$COMPILER "$FILE"; then
    log_err "Failed to compile \`$FILE\`"
    return 1
  fi

  log_ok "Running program..."
  log_ok "-------------------------OUTPUT-----------------------------"
  
  timeout "$TIMEOUT_TIME" ./"$EXE_FILE"
  TIMEOUT_RET=$?

  log_ok "------------------------------------------------------------"

  if [ $TIMEOUT_RET -eq  124 ]; then
    log_warn "Program timed out after $TIMEOUT_TIME"
  fi

  rm "$ASM_FILE"
  rm "$EXE_FILE"

  return 0
}

ensure_mycology_exists

expect_file "$COMPILER"
expect_file "$MYCOLOGY_NAME"

test "$MYCOLOGY_NAME/sanity.bf" "1s"
test "$MYCOLOGY_NAME/mycology.b98"
test "$MYCOLOGY_NAME/mycorand.bf"
test "$MYCOLOGY_NAME/mycouser.b98"

log_ok "Tests complete"


