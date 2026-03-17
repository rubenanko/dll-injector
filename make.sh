INPUT_DLL=$1

if [ -d build ]; then
rm -Rf build
fi

mkdir build

# compiling
echo assembling src/utils/direct-syscalls.asm
nasm -f win64 src/utils/direct-syscalls.asm -o build/direct-syscalls.o

echo assembling src/asm-stub.asm
nasm -f bin src/asm-stub.asm -o build/asm-stub.bin

echo building the header file for asm-stub.asm
xxd -i build/asm-stub.bin > include/asm-stub-bin.h
echo -e "DOT_TEXT\n$(cat include/asm-stub-bin.h)" > include/asm-stub-bin.h

echo compiling c files

echo src/utils/memory.c
x86_64-w64-mingw32-gcc -Iinclude -c src/utils/memory.c -o build/memory.o -Os -ffreestanding -nostdlib 

echo src/utils/peb-lookup.c
x86_64-w64-mingw32-gcc -Iinclude -c src/utils/peb-lookup.c -o build/peb-lookup.o -Os -ffreestanding -nostdlib

echo src/dll-injector.c
x86_64-w64-mingw32-gcc -Iinclude -c src/dll-injector.c -o build/dll-injector.o -Os -ffreestanding -nostdlib

echo src/loader-stub.c
x86_64-w64-mingw32-gcc -Iinclude -c src/loader-stub.c -o build/loader-stub.o -Os -ffreestanding -nostdlib

echo src/pe-parser.c
x86_64-w64-mingw32-gcc -Iinclude -c src/pe-parser.c -o build/pe-parser.o -Os -ffreestanding -nostdlib

echo building the main.c file from the template
python src/encrypt.py $INPUT_DLL
x86_64-w64-mingw32-gcc -Iinclude -c build/main.c -o build/main.o -Os -ffreestanding -nostdlib
rm build/main.c
rm include/asm-stub-bin.h
rm build/asm-stub.bin

OBJ_FILES=($(ls build/*))

echo linking "${OBJ_FILES[*]}"
x86_64-w64-mingw32-ld ${OBJ_FILES[*]} -o build/combined.o -e WinMain -nostdlib
echo extracting the shellcode
# x86_64-w64-mingw32-gcc -o build/shellcode.exe ${OBJ_FILES[*]} -Wl,--omagic \
#   -Wl,--disable-nxcompat \
#   -Wl,--disable-dynamicbase \
#   -lkernel32 -mconsole
  
x86_64-w64-mingw32-objcopy -O binary --only-section=.text build/combined.o build/shellcode.bin
echo done