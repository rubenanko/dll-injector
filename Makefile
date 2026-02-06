SHELL := /usr/bin/env bash

# ---- Toolchain ----
CC      := x86_64-w64-mingw32-gcc
WINDRES := x86_64-w64-mingw32-windres

# ---- Layout ----
BD      := build
SHARE   := ~/windows_share

# ---- Build mode ----
MODE ?= release
ifeq ($(MODE),debug)
  OPT := -O0 -g3
else
  OPT := -O2 -s
endif

# ---- Common flags ----
CPPFLAGS := -I. -DWIN32_LEAN_AND_MEAN
CFLAGS   := $(OPT) -std=c11 -Wall -Wextra -Wshadow
LDFLAGS  :=

# ---- Targets (declare what you build) ----
EXE := dll-injector
DLL := injected-dll

# ---- Sources mapping (1 line per target) ----
dll-injector_SRC := main.c dll-injector.c
dll-injector_LIB :=

injected-dll_SRC := simple-dll.c
injected-dll_LIB := -luser32 -lshell32 -lgdi32

# ---- Derived paths ----
EXE_OUT := $(EXE:%=$(BD)/%.exe)
DLL_OUT := $(DLL:%=$(BD)/%.dll)

.PHONY: all clean copy ccdb debug release
all: $(EXE_OUT) $(DLL_OUT)

debug:
	@$(MAKE) MODE=debug all

release:
	@$(MAKE) MODE=release all

$(BD):
	@mkdir -p $(BD)

# ---- Build rules ----
.SECONDEXPANSION:

# EXE rule: link directly from sources
$(BD)/%.exe: $$($$*_SRC) | $(BD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDFLAGS) $($*_LIB)

# DLL rule: same idea, but with DLL-specific link flags + auto implib/def
$(BD)/%.dll: $$($$*_SRC) | $(BD)
	$(CC) -shared $(CPPFLAGS) $(CFLAGS) -ffunction-sections -fdata-sections \
	  -o $@ $^ $(LDFLAGS) $($*_LIB) \
	  -Wl,--gc-sections -Wl,--strip-all -Wl,--build-id=none \
	  -Wl,--out-implib,$(BD)/lib$*.a \
	  -Wl,--output-def,$(BD)/$*.def

copy: all
	@cp -f $(EXE_OUT) $(DLL_OUT) $(SHARE)/ 2>/dev/null || true

clean:
	@rm -rf $(BD) compile_commands.json

# Optional: generate compile_commands.json for clangd (requires bear)
ccdb: clean
	@bear -- $(MAKE) all
