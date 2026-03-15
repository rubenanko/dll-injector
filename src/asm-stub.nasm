BITS 64

section .text
global _start

_start:
  and rsp, -16  ; Alignement de la pile (ABI Windows x64)
  sub rsp, 0x10 ; Réservation d'un slot pour pData (maintien de l'alignement à 16 octets)
  mov [rsp], rcx ; Sauvegarde de pData sur la pile avant tout appel

  ; ---------------------------------------------------------
  ; Initialisation et recherche de Kernel32 via le PEB
  ; ---------------------------------------------------------
  call get_ldr_head
  test rax, rax
  jz die
  mov r14, rax ; R14 = sentinelle (tête de liste)

  lea rcx, [rel w_kernel32]
  mov rdx, r14
  call walk_to_module_dllbase
  test rax, rax
  jz die
  mov r15, rax ; R15 = DllBase de Kernel32

  ; ---------------------------------------------------------
  ; Validation du PE Header et de l'EAT de Kernel32
  ; ---------------------------------------------------------
  mov rcx, r15 ; RCX = DllBase
  call get_export_ctx
  test rax, rax
  jz die

  mov r12, rax ; R12 = DllBase (contexte d'export)

  ; ---------------------------------------------------------
  ; Résolution des fonctions de résolution dynamique
  ; ---------------------------------------------------------

  ; --- Résolution de GetModuleHandleA ---
  lea rdx, [rel a_GetModuleHandleA] ; RDX = "GetModuleHandleA"
  mov rcx, r12 ; RCX = contexte (Base)
  call resolve_export_by_name
  test rax, rax
  jz die
  mov r13, rax ; R13 = pGetModuleHandleA

  ; --- Résolution de GetProcAddress ---
  lea rdx, [rel a_GetProcAddress] ; RDX = "GetProcAddress"
  mov rcx, r12 ; RCX = contexte (Base)
  call resolve_export_by_name
  test rax, rax
  jz die
  mov r14, rax ; R14 = pGetProcAddress

  ; --- Résolution de LoadLibraryA ---
  lea rdx, [rel a_LoadLibraryA]
  mov rcx, r12                   ; RCX = DllBase de Kernel32
  call resolve_export_by_name
  test rax, rax
  jz die

  ; --- Complétion de la structure MANUAL_MAPPING_DATA ---
  ; RBX chargé ici, après walk_to_module_dllbase qui écrase BX (comparaison wide-char)
  mov rbx, [rsp]                 ; RBX = pData (depuis la pile)
  mov [rbx + 0x00], rax          ; pData->pLoadLibraryA
  mov [rbx + 0x08], r14          ; pData->pGetProcAddress

  ; --- Appel de C_LoaderStub(pData) ---
  mov rcx, rbx
  call [rbx + 0x18]              ; pData->pCStubAddress(pData)

  ; --- Appel de ExitThread via résolution dynamique ---
  lea rcx, [rel a_kernel32]
  call r13 ; GetModuleHandleA -> RAX = handle kernel32.dll
  mov rcx, rax
  lea rdx, [rel a_ExitThread]
  call r14 ; GetProcAddress -> RAX = adresse d'ExitThread

  xor rcx,rcx ; Code de sortie nul
  call rax


die:
  int 3
  xor rax,rax
  mov [rax],0 ; Segfault intentionnel


; =============================================================
; get_ldr_head
; Retourne un pointeur vers la tête de InMemoryOrderModuleList (PEB).
; SORTIE : RAX = head (LIST_ENTRY*)
; =============================================================
get_ldr_head:
  xor rax, rax
  mov rax, gs:[0x60] ; Adresse du PEB (TEB.ProcessEnvironmentBlock)
  ; Conformément aux exigences d'alignement des structures :
  ; 4 octets d'espacement entre Reserved[2] et Reserved[3]
  mov rax, [rax + 0x18] ; Adresse de PEB_LDR_DATA
  add rax, 0x20 ; Adresse de InMemoryOrderModuleList
  ret

; =============================================================
; walk_to_module_dllbase
; ENTRÉE : RCX = WCHAR* nom du module recherché
; ENTRÉE : RDX = pointeur vers la tête de liste (PEB)
; SORTIE  : RAX = DllBase ou 0 si introuvable
; =============================================================
walk_to_module_dllbase:
    mov r8, rdx ; R8 = sauvegarde de la sentinelle pour fin de boucle
    mov rdx, [rdx] ; RDX = premier module (Flink)

_scan_loop:
    cmp rdx, r8
    je _not_found ; Module non trouvé
    push rdx ; Sauvegarde du nœud courant
    push rcx ; Sauvegarde du pointeur de chaîne "KERNEL32..."
    mov rsi, [rdx + 0x50] ; RSI = pointeur vers le nom du module courant
    mov rdi, rcx
    test rsi, rsi ; Buffer null ?
    jz _next_candidate

_compare_char:
    mov ax, [rsi]
    mov bx, [rdi]
    cmp ax, bx
    jne _next_candidate
    test ax, ax
    jz _found_match
    add rsi, 2
    add rdi, 2
    jmp _compare_char

_next_candidate:
    pop rcx
    pop rdx
    mov rdx, [rdx] ; Avance au suivant (Flink à l'offset 0x00)
    jmp _scan_loop

_found_match:
    pop rcx
    pop rax ; RAX = nœud courant (anciennement dans RDX)
    mov rax, [rax + 0x20] ; Récupère DllBase (offset 0x30 − 0x10)
    ret

_not_found:
    xor rax, rax
    ret

; =============================================================
; get_export_ctx
; Vérifie que le module possède un PE Header valide et une EAT.
; ENTRÉE : RCX = DllBase
; SORTIE  : RAX = DllBase (contexte) ou 0 si invalide
; =============================================================
get_export_ctx:
  mov eax, [rcx + 0x3C] ; e_lfanew (offset vers le PE Header)
  add rax, rcx ; RAX = adresse du PE Header

  ; Vérification de la signature "PE\0\0"
  cmp dword [rax], 0x00004550
  jne .fail

  ; Vérification de la présence de l'Export Directory
  ; Offset 0x88 = DataDirectory[0].VirtualAddress (Export)
  mov edx, [rax + 0x88]
  test edx, edx
  jz .fail

  mov rax, rcx ; Succès : retourne la Base comme contexte
  ret
.fail:
  xor rax, rax
  ret

; =============================================================
; resolve_export_by_name
; Recherche une fonction par son nom ASCII dans l'EAT.
; ENTRÉE : RCX = DllBase (contexte)
; ENTRÉE : RDX = pointeur vers la chaîne ASCII (ex. : "GetProcAddress")
; SORTIE  : RAX = adresse virtuelle (VA) de la fonction ou 0
; =============================================================
resolve_export_by_name:
  push rbx
  push rsi
  push rdi
  push r12

  mov r8, rcx ; R8 = DllBase
  mov r9, rdx ; R9 = chaîne cible

  ; 1. Accès à l'Export Directory
  mov eax, [r8 + 0x3C] ; e_lfanew
  add rax, r8 ; PE Header
  mov eax, [rax + 0x88] ; RVA de l'Export Directory
  add rax, r8 ; RAX = VA de l'Export Directory
  mov r10, rax ; R10 pointe sur IMAGE_EXPORT_DIRECTORY

  ; 2. Récupération des pointeurs clés
  mov ecx,  [r10 + 0x18] ; ECX = NumberOfNames (compteur de boucle)
  mov r11d, [r10 + 0x20] ; RVA de AddressOfNames
  add r11, r8 ; R11 = VA de AddressOfNames (tableau de RVA)

  ; 3. Boucle de recherche (de NumberOfNames-1 jusqu'à 0)
.loop_find:
  jecxz .not_found ; Compteur nul → non trouvé
  dec rcx ; Index courant

  mov edx, [r11 + rcx*4] ; RDX = RVA du nom (DWORD)
  add rdx, r8 ; RDX = VA du nom (chaîne ASCII)

  ; Comparaison (RDX vs R9)
  call _strcmp_ascii
  test eax, eax ; 0 = correspondance
  jnz .loop_find ; Pas de correspondance → suivant

  ; 4. Correspondance trouvée : récupération de l'adresse
  ; A) Récupération de l'ordinal
  mov r12d, [r10 + 0x24] ; RVA de AddressOfNameOrdinals
  add r12, r8
  movzx edx, word [r12 + rcx*2] ; EDX = ordinal (WORD)

  ; B) Récupération de l'adresse de la fonction
  mov r12d, [r10 + 0x1c] ; RVA de AddressOfFunctions
  add r12, r8
  mov eax, [r12 + rdx*4] ; RAX = RVA de la fonction
  add rax, r8 ; RAX = VA de la fonction (adresse finale)

  jmp .done

.not_found:
  xor rax, rax

.done:
  pop r12
  pop rdi
  pop rsi
  pop rbx
  ret

; Sous-routine : strcmp ASCII (R9 = cible, RDX = courant)
; Modifie RSI, RDI, AL, BL. Préservés par l'appelant.
_strcmp_ascii:
  push rsi
  push rdi
  mov rsi, rdx
  mov rdi, r9
.cmp_loop:
  mov al, byte [rsi]
  cmp al, byte [rdi]   ; Comparaison directe, évite d'écraser BL (= octet faible de pData)
  jne .diff
  test al, al
  jz .match
  inc rsi
  inc rdi
  jmp .cmp_loop
.diff:
  mov eax, 1
  jmp .end_cmp
.match:
  xor eax, eax
.end_cmp:
  pop rdi
  pop rsi
  ret

; =============================================================
; DONNÉES
; =============================================================
w_kernel32: dw 'K','E','R','N','E','L','3','2','.','D','L','L', 0
a_GetProcAddress: db 'GetProcAddress', 0
a_GetModuleHandleA: db 'GetModuleHandleA', 0
a_ExitThread: db 'ExitThread', 0
a_LoadLibraryA: db 'LoadLibraryA', 0
a_USER32MODULENAME: db 'USER32', 0
a_MessageBoxA: db 'MessageBoxA', 0
a_kernel32: db 'kernel32.dll', 0
a_user32: db 'user32.dll', 0
