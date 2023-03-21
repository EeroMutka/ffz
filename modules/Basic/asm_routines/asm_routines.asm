default rel
bits 64

global memmove
global memcpy
global memset

section .text

; NOTE: everything in this file has ms-x64 calling convention, so currently only works in windows.

; rcx: destination
; rdx: source
; r8: size
memcpy:
	mov rax, rcx ; return the destination
	
	mov rdi, rcx
	mov rsi, rdx
	mov rcx, r8 ; repetition count
	rep movsb
	
	ret

; rcx: base
; rdx: value
; r8: size
memset:
	mov r10, rcx ; preserve the base address
	
	mov al, dl
	mov rcx, r8; repetition count
	rep stosb
	
	mov rax, r10
	ret

; rcx: destination
; rdx: source
; r8: size
memmove:
	mov rax, rcx ; return the destination
	
	mov rdi, rcx
	mov rsi, rdx
	
	cmp rcx, rdx
	je .done ; if dst == src, we don't need to do anything
	jb .fast ; if dst < src, we can do fast move forwards
	
	; If dst >= src + size, the regions don't overlap and we can do fast move forwards
	add rdx, r8
	cmp rdi, rdx
	jae .fast
.slow:
	; TODO: better implementation of the slow path, rep movsb backwards is not fast at all.
	
	std ; set direction flag to make movsb go backwards
	
	mov rcx, r8 ; repetition count
	
	dec r8
	add rsi, r8 ; start from rsi + size - 1
	add rdi, r8 ; start from rdi + size - 1
	
	rep movsb
	
	cld ; clear the direction flag
	ret
.fast:
	mov rcx, r8 ; repetition count
	rep movsb
.done:
	ret
