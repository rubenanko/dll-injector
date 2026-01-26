x86_64-w64-mingw32-gcc src/main.c -o dll-injector.exe \
  -nostdlib -nodefaultlibs \
  -lkernel32 \
  # -mwindows # disable the console