; https://gist.github.com/esoterix/df38008568c50d4f83123e3a90b62ebb
include ksamd64.inc
extern InstrumentationCallback:proc
extern New_LdrpCallInitRoutine:proc
extern GetEntryRegSlot:proc
EXTERNDEF __imp_RtlCaptureContext:QWORD

.code
InstrHook proc

    mov  gs:[2e0h], rsp            ; Win10 TEB InstrumentationCallbackPreviousSp
    mov  gs:[2d8h], r10            ; Win10 TEB InstrumentationCallbackPreviousPc
    mov  r10, rcx                  ; Save original RCX
    sub  rsp, 4d0h                 ; Alloc stack space for CONTEXT structure
    and  rsp, -10h                 ; RSP must be 16 byte aligned before calls
    mov  rcx, rsp
    call __imp_RtlCaptureContext   ; Save the current register state. RtlCaptureContext does not require shadow space
    sub  rsp, 20h                  ; Shadow space
    call InstrumentationCallback   ; Call main instrumentation routine

InstrHook  endp

; Entry shim for the LdrpCallInitRoutine hook.  The pre-trampoline reaches this via
; 'jmp h->new_func' with the hooked caller's non-volatile registers (r12-r15) still
; intact -- i.e. exactly the values the malware had when it entered the loader.  We
; snapshot them into thread-local storage before the C handler's prologue can reuse
; them as scratch, then tail-jump into the real handler with the arguments untouched.
public Capture_LdrpCallInitRoutine
Capture_LdrpCallInitRoutine proc
    push rcx                       ; preserve hooked args across the C call
    push rdx
    push r8
    push r9
    sub rsp, 28h                   ; shadow space + alignment (rsp now 16-byte aligned)
    call GetEntryRegSlot           ; rax -> ULONG_PTR[4]; r12-r15 preserved (ABI)
    mov [rax], r12
    mov [rax+8], r13
    mov [rax+10h], r14
    mov [rax+18h], r15
    add rsp, 28h
    pop r9
    pop r8
    pop rdx
    pop rcx
    jmp New_LdrpCallInitRoutine    ; tail-call the real handler; stack/args as on entry
Capture_LdrpCallInitRoutine endp

; Call the original function with the non-volatile registers captured at hook entry,
; rather than the C handler's scratch values.  This makes any target code re-entered
; synchronously through the original (LdrpCallInitRoutine -> DllMain -> VM resolver)
; observe the caller's true r12-r15, while still restoring the handler's own r12-r15
; afterwards so the handler stays ABI-correct.
; ULONG_PTR CallOriginalWithEntryRegs(PVOID target, ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3, ULONG_PTR a4)
public CallOriginalWithEntryRegs
CallOriginalWithEntryRegs proc frame
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 30h
    .allocstack 30h
    .endprolog

    ; incoming: rcx=target, rdx=a1, r8=a2, r9=a3, a4 at [rsp+90h]
    mov rbx, rcx                   ; target (non-volatile, survives GetEntryRegSlot)
    mov rsi, rdx                   ; a1
    mov rdi, r8                    ; a2
    mov [rsp+20h], r9              ; stash a3 (above outgoing shadow space)
    mov rax, [rsp+90h]             ; a4
    mov [rsp+28h], rax             ; stash a4

    call GetEntryRegSlot           ; rax -> ULONG_PTR[4]

    mov r12, [rax]                 ; reload the caller's entry non-volatiles
    mov r13, [rax+8]
    mov r14, [rax+10h]
    mov r15, [rax+18h]

    mov rcx, rsi                   ; a1
    mov rdx, rdi                   ; a2
    mov r8, [rsp+20h]              ; a3
    mov r9, [rsp+28h]              ; a4
    call rbx                       ; original(a1,a2,a3,a4) with entry r12-r15

    add rsp, 30h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
CallOriginalWithEntryRegs endp

end