; syscall-stub.nasm — Generic Syscall Execution Stub
;
; Provides a single reusable syscall stub instead of one per NT function.
; The caller sets the SSN via SetSSN(), then invokes RunSyscall() which
; mimics the ntdll syscall stub layout (mov r10,rcx / mov eax,SSN / syscall).
;
; Build: nasm -f win64 syscall-stub.nasm -o syscall-stub.o

global SetSSN
global RunSyscall
global g_current_ssn

section .data
g_current_ssn:  dd 0

section .text

; void SetSSN(DWORD ssn)
; RCX = syscall number
SetSSN:
    mov dword [rel g_current_ssn], ecx
    ret

; NTSTATUS RunSyscall(...)
; All parameters are passed through untouched (RCX, RDX, R8, R9, stack).
; The syscall number is read from g_current_ssn.
RunSyscall:
    mov r10, rcx
    mov eax, dword [rel g_current_ssn]
    syscall
    ret
