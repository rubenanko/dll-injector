x86_64-w64-mingw32-gcc -Iinclude test.c -c
x86_64-w64-mingw32-gcc -Iinclude src/utils/log.c -c
x86_64-w64-mingw32-gcc -Iinclude src/pe-parser.c -c
x86_64-w64-mingw32-gcc -Iinclude src/utils/stdio-sec.c -c

x86_64-w64-mingw32-gcc pe-parser.o stdio-sec.o log.o test.o -o test.exe
