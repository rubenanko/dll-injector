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
SYSCALLS_OBJ := $(BD)/direct-syscalls.obj

dll-injector_SRC := $(SRC_DIR)/main.c $(SRC_DIR)/dll-injector.c $(SRC_DIR)/pe-parser.c $(SRC_DIR)/loader-stub.c $(SRC_DIR)/utils/stdio-sec.c $(SRC_DIR)/utils/peb-lookup.c $(SRC_DIR)/utils/memory.c
dll-injector_LIB :=

injected-dll_SRC := $(SRC_DIR)/simple-dll.c
injected-dll_LIB := -luser32 -lshell32 -lgdi32

# ---- Derived paths ----
EXE_OUT  := $(BD)/$(EXE).exe
DLL_OUT  := $(BD)/$(DLL).dll
ASM_BIN  := $(BD)/asm-stub.bin
ASM_HDR  := $(BD)/asm-stub-bin.h
MAIN_GEN := $(SRC_DIR)/main.c

.PHONY: all clean clean-docs docs copy ccdb debug release
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

# Compile direct syscall stubs (NASM win64 COFF object)
$(SYSCALLS_OBJ): $(SRC_DIR)/utils/direct-syscalls.asm | $(BD)
	nasm -f win64 $< -o $@

# Generate main.c by embedding the compiled DLL into the template
$(MAIN_GEN): $(DLL_OUT) $(SRC_DIR)/encrypt.py $(SRC_DIR)/main.tpl.c
	cd $(SRC_DIR) && python3 encrypt.py ../$(DLL_OUT)

# dll-injector.exe depends on the generated header (order-only) and syscall object (normal dep)
$(BD)/dll-injector.exe: $(SYSCALLS_OBJ) $(MAIN_GEN) | $(ASM_HDR)

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

docs:
	cd docs && doxygen Doxyfile

clean-docs:
	@rm -rf docs/html docs/latex

ccdb: clean
	@bear -- $(MAKE) all
