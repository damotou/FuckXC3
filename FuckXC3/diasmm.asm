
EXTERN jmp_ObpCreateHandle_1:QWORD;
EXTERN jmp_ObpCreateHandle_2:QWORD;

.CODE

;*************************************************************
;*************************************************************
pushaq MACRO
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
        push rbp	; rsp
        push rbx
        push rdx
        push rcx
        push rax
ENDM
;*************************************************************
;*************************************************************


;*************************************************************
;*************************************************************
popaq MACRO
        pop rax
        pop rcx
        pop rdx
        pop rbx
        pop rbp		; rsp
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
ENDM
;*************************************************************
;*************************************************************


;*************************************************************
;*************************************************************
ObpCreateHandle_1 PROC


mov     eax, [rbx+10h]
mov     [rbx+10h], r13d
mov     r9, rdx
or      [rbx+14h], eax
mov     rax, [rsp+0B8h]
lea     rcx, [rbx+20h]  
mov     eax, [rax+5Ch]
pushfq
cmp		eax,0
jne		__ret__

mov		eax,1f000fh

__ret__:

popfq
jmp		jmp_ObpCreateHandle_1
ObpCreateHandle_1 ENDP
;*************************************************************
;*************************************************************

;*************************************************************
;*************************************************************
ObpCreateHandle_2 PROC
mov     edx, [rsp+50h]
mov     r8, [rsp+118h]
movzx   eax, byte ptr [r8-18h]
lea     r14, [r8-30h]
mov     rbp, [r15+rax*8]
mov     eax, [rbp+5Ch]

pushfq
cmp		eax,0
jne		__ret__

mov		eax,1f000fh

__ret__:

popfq
jmp		jmp_ObpCreateHandle_2

ObpCreateHandle_2 ENDP
;*************************************************************
;*************************************************************

_read_r12 PROC
mov		rax,r12
ret
_read_r12 ENDP


END