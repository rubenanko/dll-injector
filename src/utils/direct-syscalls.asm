global dCreateThreadEx
global dAllocateVirtualMemory
global dProtectVirtualMemory
global dReadVirtualMemory
global dWriteVirtualMemory
global dOpenProcess

section .text

dCreateThreadEx:
    mov rax,0x00c9 
    mov r10,rcx
    syscall
    ret

dAllocateVirtualMemory:
    mov rax,0x0018 
    mov r10,rcx
    syscall
    ret

dProtectVirtualMemory:
    mov rax,0x0050 
    mov r10,rcx
    syscall
    ret

dReadVirtualMemory:
    mov rax,0x003f 
    mov r10,rcx
    syscall
    ret

dWriteVirtualMemory:
    mov rax,0x003a
    mov r10,rcx
    syscall
    ret

dOpenProcess:
    mov rax,0x0026
    mov r10,rcx
    syscall
    ret