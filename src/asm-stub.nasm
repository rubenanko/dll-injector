[BITS 64]

section .text

global asm_stub_entry

; Structure MANUAL_MAPPING_DATA (offsets)
; pLoadLibraryA    : +0x00
; pGetProcAddress  : +0x08
; pBaseAddress     : +0x10
; pCStubAddress    : +0x18

asm_stub_entry:
    ; Le thread commence ici. RCX contient le pointeur vers MANUAL_MAPPING_DATA (pData)
    ; On doit sauvegarder le contexte si nécessaire, mais ici on va surtout initialiser la structure.
    
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 0x28           ; Shadow space pour les appels de fonctions

    mov r12, rcx            ; R12 = pData

    ; 1. Trouver KERNEL32.DLL via le PEB
    call get_kernel32_base
    test rax, rax
    jz .exit_stub
    mov r13, rax            ; R13 = Kernel32 Base

    ; 2. Résoudre GetProcAddress
    mov rcx, r13
    lea rdx, [rel a_GetProcAddress]
    call resolve_export_by_name
    test rax, rax
    jz .exit_stub
    mov [r12 + 0x08], rax   ; pData->pGetProcAddress = rax
    mov r14, rax            ; R14 = GetProcAddress

    ; 3. Résoudre LoadLibraryA
    mov rcx, r13
    lea rdx, [rel a_LoadLibraryA]
    call resolve_export_by_name
    test rax, rax
    jz .exit_stub
    mov [r12 + 0x00], rax   ; pData->pLoadLibraryA = rax

    ; 4. Appeler le C_LoaderStub(pData)
    mov rcx, r12            ; RCX = pData
    mov rax, [r12 + 0x18]   ; RAX = pData->pCStubAddress
    call rax

.exit_stub:
    add rsp, 0x28
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

; --- Helpers (inspirés de shellcode.nasm) ---

get_kernel32_base:
    mov rax, gs:[0x60]      ; PEB
    mov rax, [rax + 0x18]   ; PEB_LDR_DATA
    mov rax, [rax + 0x20]   ; InMemoryOrderModuleList (head)
    mov rsi, [rax]          ; Premier module (ntdll)
    mov rsi, [rsi]          ; Deuxième module (kernel32)
    mov rax, [rsi + 0x20]   ; DllBase (InMemoryOrderLinks est à +0x10 dans LDR_DATA_TABLE_ENTRY, DllBase est à +0x30)
    ret

resolve_export_by_name:
    ; RCX = DllBase, RDX = Function Name
    push rbx
    push rsi
    push rdi
    
    mov r8, rcx             ; R8 = DllBase
    mov r9, rdx             ; R9 = Target Name
    
    mov eax, [r8 + 0x3C]    ; e_lfanew
    add rax, r8             ; PE Header
    mov eax, [rax + 0x88]   ; Export Directory RVA
    add rax, r8             ; Export Directory VA
    mov r10, rax            ; R10 = Export Directory
    
    mov ecx, [r10 + 0x18]   ; NumberOfNames
    mov r11d, [r10 + 0x20]  ; AddressOfNames RVA
    add r11, r8             ; AddressOfNames VA
    
.loop_find:
    jecxz .not_found
    dec rcx
    mov edx, [r11 + rcx*4]  ; Name RVA
    add rdx, r8             ; Name VA
    
    ; Comparaison manuelle simple
    push rcx
    mov rsi, rdx
    mov rdi, r9
.cmp_loop:
    mov al, [rsi]
    mov bl, [rdi]
    cmp al, bl
    jne .cmp_diff
    test al, al
    jz .cmp_match
    inc rsi
    inc rdi
    jmp .cmp_loop
.cmp_diff:
    pop rcx
    jmp .loop_find
.cmp_match:
    pop rcx
    
    ; Match trouvé
    mov r11d, [r10 + 0x24]  ; AddressOfNameOrdinals RVA
    add r11, r8
    movzx edx, word [r11 + rcx*2] ; Ordinal
    
    mov r11d, [r10 + 0x1C]  ; AddressOfFunctions RVA
    add r11, r8
    mov eax, [r11 + rdx*4]  ; Function RVA
    add rax, r8             ; Function VA
    jmp .done

.not_found:
    xor rax, rax
.done:
    pop rdi
    pop rsi
    pop rbx
    ret

a_GetProcAddress: db 'GetProcAddress', 0
a_LoadLibraryA: db 'LoadLibraryA', 0
