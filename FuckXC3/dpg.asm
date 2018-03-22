EXTERN g_CpuContextAddress:QWORD;
EXTERN OnRtlCaptureContext:PROC;
EXTERN g_KiRetireDpcList:QWORD;

.CODE
public AdjustStackCallPointer
AdjustStackCallPointer PROC
    mov rsp, rcx
    xchg r8, rcx
    jmp rdx
AdjustStackCallPointer ENDP

public GetCpuIndex
GetCpuIndex PROC
  mov     al, gs:[52h]
  movzx   eax, al
  ret
GetCpuIndex ENDP


public RestoreCpuContext
RestoreCpuContext PROC
         push    rax
         sub     rsp, 20h
                 call    GetCpuIndex
                 add     rsp, 20h
                 mov     r11, 170h
                 mul     r11
                 mov     r11, rax
                 add     r11, g_CpuContextAddress
                 pop     rax
                 mov     rsp, [r11+48h]
                 mov     rbx, [r11+40h]
                 mov     [rsp+0], rbx
                 movdqa  xmm0, xmmword ptr [r11+50h]
         movdqa  xmm1, xmmword ptr [r11+60h]
                 movdqa  xmm2, xmmword ptr [r11+70h]
                 movdqa  xmm3, xmmword ptr [r11+80h]
                 movdqa  xmm4, xmmword ptr [r11+90h]
                 movdqa  xmm5, xmmword ptr [r11+0A0h]
                 movdqa  xmm6, xmmword ptr [r11+0B0h]
                 movdqa  xmm7, xmmword ptr [r11+0C0h]
                 movdqa  xmm8, xmmword ptr [r11+0D0h]
                 movdqa  xmm9, xmmword ptr [r11+0E0h]
                 movdqa  xmm10, xmmword ptr [r11+0F0h]
                 movdqa  xmm11, xmmword ptr [r11+100h]
                 movdqa  xmm12, xmmword ptr [r11+110h]
                 movdqa  xmm13, xmmword ptr [r11+120h]
         movdqa  xmm14, xmmword ptr [r11+130h]
         movdqa  xmm15, xmmword ptr [r11+140h]
         mov     rbx, [r11]
                 mov     rsi, [r11+8]
                 mov     rdi, [r11+10h]
                 mov     rbp, [r11+18h]
                 mov     r12, [r11+20h]
                 mov     r13, [r11+28h]
                 mov     r14, [r11+30h]
                 mov     r15, [r11+38h]
                 mov     rcx, [r11+150h]
                 mov     rdx, [r11+158h]
                 mov     r8, [r11+160h]
                 mov     r9, [r11+168h]
                 ret
RestoreCpuContext ENDP

public BackTo1942
BackTo1942 PROC
         sub     rsp, 20h ;时光倒流
                 call    GetCpuIndex
                 add     rsp, 20h
                 mov     r11, 170h
                 mul     r11
                 mov     r11, rax
                 add     r11, g_CpuContextAddress
                 mov     rax, [r11+40h]
                 sub     rax, 5
                 mov     [r11+40h], rax  ; 这里直接RIP=RIP-5，也就是回到Call KiXX的5字节指令
                 jmp     RestoreCpuContext
BackTo1942 ENDP

public HookKiRetireDpcList
HookKiRetireDpcList PROC
                 push    rcx
                 push    rdx
                 push    r8
                 push    r9
                 sub     rsp, 20h
                 call    GetCpuIndex
                 add     rsp, 20h
                 pop     r9
                 pop     r8
                 pop     rdx
                 pop     rcx
                 mov     r11, 170h
                 mul     r11
                 add     rax, g_CpuContextAddress ; RAX = g_CpuContext[CpuIndex]
                 mov     [rax], rbx
                 mov     [rax+8], rsi
                 mov     [rax+10h], rdi
                 mov     [rax+18h], rbp
                 mov     [rax+20h], r12
                 mov     [rax+28h], r13
                 mov     [rax+30h], r14
                 mov     [rax+38h], r15
                 movdqa  xmmword ptr [rax+50h], xmm0
                 movdqa  xmmword ptr [rax+60h], xmm1
                 movdqa  xmmword ptr [rax+70h], xmm2
                 movdqa  xmmword ptr [rax+80h], xmm3
                 movdqa  xmmword ptr [rax+90h], xmm4
                 movdqa  xmmword ptr [rax+0A0h], xmm5
                 movdqa  xmmword ptr [rax+0B0h], xmm6
                 movdqa  xmmword ptr [rax+0C0h], xmm7
                 movdqa  xmmword ptr [rax+0D0h], xmm8
                 movdqa  xmmword ptr [rax+0E0h], xmm9
                 movdqa  xmmword ptr [rax+0F0h], xmm10
                 movdqa  xmmword ptr [rax+100h], xmm11
                 movdqa  xmmword ptr [rax+110h], xmm12
                 movdqa  xmmword ptr [rax+120h], xmm13
                 movdqa  xmmword ptr [rax+130h], xmm14
                 movdqa  xmmword ptr [rax+140h], xmm15
                 mov     [rax+150h], rcx
                 mov     [rax+158h], rdx
                 mov     [rax+160h], r8
                 mov     [rax+168h], r9
                 mov     r11, [rsp]
                 mov     [rax+40h], r11
                 mov     r11, rsp
                 mov     [rax+48h], r11
         lea     rax, RestoreCpuContext
         mov   [rsp],rax
         jmp   g_KiRetireDpcList
HookKiRetireDpcList ENDP

public HookRtlCaptureContext
HookRtlCaptureContext PROC
  push rsp
  pushfq
  push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8        
    push rdi
    push rsi
    push rbp
  push rbx
    push rdx
    push rcx
    push rax
  mov rcx,rsp
  sub rsp,28h
  call OnRtlCaptureContext
  add  rsp, 28h  
    pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rbp
    pop rsi
    pop rdi 
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
  popfq
  pop rsp
  ret
HookRtlCaptureContext ENDP
END