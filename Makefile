SHELL := /usr/bin/env bash

# ---- Toolchain ----
CC      := x86_64-w64-mingw32-gcc
WINDRES := x86_64-w64-mingw32-windres

# ---- Layout ----
BD      := build
SRC_DIR := src
INC_DIR := include
SHARE   := $(HOME)/windows_share

# ---- Build mode ----
MODE ?= release
ifeq ($(MODE),debug)
  OPT := -O0 -g3
else
  OPT := -O2 -s
endif

# ---- Common flags ----
CPPFLAGS := -I$(INC_DIR) -I$(BD) -DWIN32_LEAN_AND_MEAN
CFLAGS   := $(OPT) -std=c11 -Wall -Wextra -Wshadow -fno-stack-protector
LDFLAGS  :=

# ---- Targets ----
EXE := dll-injector
DLL := injected-dll

# ---- Sources mapping ----
dll-injector_SRC := $(SRC_DIR)/main.c $(SRC_DIR)/dll-injector.c $(SRC_DIR)/pe-parser.c $(SRC_DIR)/loader-stub.c $(SRC_DIR)/utils/stdio-sec.c $(SRC_DIR)/utils/peb-lookup.c
dll-injector_LIB :=

injected-dll_SRC := $(SRC_DIR)/simple-dll.c
injected-dll_LIB := -luser32 -lshell32 -lgdi32

# ---- Derived paths ----
EXE_OUT := $(BD)/$(EXE).exe
DLL_OUT := $(BD)/$(DLL).dll
ASM_BIN := $(BD)/asm-stub.bin
ASM_HDR := $(BD)/asm-stub-bin.h

.PHONY: all clean copy ccdb debug release
all: $(EXE_OUT) $(DLL_OUT)

debug:
	@$(MAKE) MODE=debug all

release:
	@$(MAKE) MODE=release all

$(BD):
	@mkdir -p $(BD)

.SECONDEXPANSION:

$(ASM_BIN): $(SRC_DIR)/asm-stub.nasm | $(BD)
	nasm -f bin $< -o $@

# Generate a C header embedding the raw ASM stub binary
$(ASM_HDR): $(ASM_BIN)
	cd $(BD) && xxd -i asm-stub.bin > asm-stub-bin.h

# dll-injector.exe depends on the generated header (order-only: not passed to gcc)
$(BD)/dll-injector.exe: | $(ASM_HDR)

$(BD)/%.exe: $$($$*_SRC) | $(BD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDFLAGS) $($*_LIB)

$(BD)/%.dll: $$($$*_SRC) | $(BD)
	$(CC) -shared $(CPPFLAGS) $(CFLAGS) -ffunction-sections -fdata-sections \
	  -o $@ $^ $(LDFLAGS) $($*_LIB) \
	  -Wl,--gc-sections -Wl,--strip-all -Wl,--build-id=none \
	  -Wl,--out-implib,$(BD)/lib$*.a \
	  -Wl,--output-def,$(BD)/$*.def

copy: all
	@mkdir -p $(SHARE)
	@cp -f $(EXE_OUT) $(DLL_OUT) $(SHARE)/
	@echo "Copied to $(SHARE)"

clean:
	@rm -rf $(BD) compile_commands.json

ccdb: clean
	@bear -- $(MAKE) all
