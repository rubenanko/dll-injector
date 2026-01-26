#!/usr/bin/env bash

# -------- Script configuration -------- #
set -Eeuo pipefail
IFS=$'\n\t'

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd -P)
build_dir="./tmp/"

# -------- Script utils -------- #
setup_colors() {
  if [[ -t 2 ]] && [[ -z "${NO_COLOR-}" ]] && [[ "${TERM-}" != "dumb" ]]; then
    NOFORMAT='\033[0m' RED='\033[0;31m' GREEN='\033[0;32m' ORANGE='\033[0;33m' BLUE='\033[0;34m' PURPLE='\033[0;35m' CYAN='\033[0;36m' YELLOW='\033[1;33m'
  else
    NOFORMAT='' RED='' GREEN='' ORANGE='' BLUE='' PURPLE='' CYAN='' YELLOW=''
  fi
}

# msg "This is a ${RED}very important${NOFORMAT} message, but not a script output value!"
msg() {
  echo >&2 -e "${1-}"
}

info() {
  msg "${BLUE}[INFO]${NOFORMAT} ${1-}"
}

fail() {
  msg "${RED}[ERROR]${NOFORMAT} ${1-}"
  exit 1
}

setup_colors

# -------- Script verifications -------- #

# -------- Script content -------- #

# STEP 0 – Préparation
step_0() {
  if [ -d "${build_dir}" ]; then
    rm -rf "${build_dir}"
    info "build directory removed"
  fi
  mkdir -p "${build_dir}"
  info "build directory created"
}


build(){
x86_64-w64-mingw32-gcc src/main.c -o dll-injector.exe \
  -nostdlib -nodefaultlibs \
  -lkernel32 \
  # -mwindows # disable the console
}

main(){
  step_0
  build
}

main
