.const
EndianSwap db 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0

.data
ExpandedKey xmmword 11 dup(?)
Counter     xmmword ?

.code
; expand key
ExpandKey macro
	; key generation
	aeskeygenassist xmm1, xmm0, 1
	KeyGen 10h
	aeskeygenassist xmm1, xmm0, 2
	KeyGen 20h
	aeskeygenassist xmm1, xmm0, 4
	KeyGen 30h
	aeskeygenassist xmm1, xmm0, 8
	KeyGen 40h
	aeskeygenassist xmm1, xmm0, 10h
	KeyGen 50h
	aeskeygenassist xmm1, xmm0, 20h
	KeyGen 60h
	aeskeygenassist xmm1, xmm0, 40h
	KeyGen 70h
	aeskeygenassist xmm1, xmm0, 80h
	KeyGen 80h
	aeskeygenassist xmm1, xmm0, 1bh
	KeyGen 90h
	aeskeygenassist xmm1, xmm0, 36h
	KeyGen 0a0h	
endm

; perform the rest of the key expansion
KeyGen macro off
	pshufd  xmm1, xmm1, 0ffh
	vpslldq xmm2, xmm0, 4
	pxor    xmm0, xmm2
	vpslldq xmm2, xmm0, 4
	pxor    xmm0, xmm2
	vpslldq xmm2, xmm0, 4
	pxor    xmm0, xmm2
	pxor    xmm0, xmm1
	movdqa [ExpandedKey + off], xmm0
endm

; encrypt
AesEncrypt macro
	; whiten
	pxor       xmm3, [ExpandedKey + 000h]
	; round 1-9
	aesenc     xmm3, [ExpandedKey + 010h]
	aesenc     xmm3, [ExpandedKey + 020h]
	aesenc     xmm3, [ExpandedKey + 030h]
	aesenc     xmm3, [ExpandedKey + 040h]
	aesenc     xmm3, [ExpandedKey + 050h]
	aesenc     xmm3, [ExpandedKey + 060h]
	aesenc     xmm3, [ExpandedKey + 070h]
	aesenc     xmm3, [ExpandedKey + 080h]
	aesenc     xmm3, [ExpandedKey + 090h]
	; final round
	aesenclast xmm3, [ExpandedKey + 0a0h]
endm

; increment counter
IncrementCounter macro
	; BE->LE
	pshufb  xmm4, EndianSwap
	; rax:rbx = xmm4
	pextrq  rax, xmm4, 0
	pextrq  rbx, xmm4, 1
	; rax++
	add     rax, 1
	; carry?
	adc     rbx, 0
	; xmm4 = rax:rbx
	pinsrq  xmm4, rax, 0
	pinsrq  xmm4, rbx, 1
	; LE->BE
	pshufb  xmm4, EndianSwap
endm

; xmm0: key, xmm3: iv
AesCtrInit proc
	; load key
	movdqa ExpandedKey, xmm0
	; expand key
	ExpandKey
	; load iv
	movdqa Counter, xmm3
	ret
AesCtrInit endp

; rcx: data, rdx: length
AesCtrCrypt proc
	; move iv to xmm4
	movdqa xmm4, Counter
aes_loop:
	; move counter to xmm3 for encryption
	movdqa xmm3, xmm4
	; encrypt
	AesEncrypt
	cmp rdx, 10h       ; smaller than 0x10 block?
	jl  aes_under_loop ; if yes, do byte-at-a-time xor
	; xor 0x10 block with (plain/cipher)text
	movdqu xmm5, [rcx]
	pxor   xmm5, xmm3
	movdqu [rcx], xmm5
	; increment counter
	IncrementCounter
	; data += 0x10, length -= 0x10
	add rcx, 10h
	sub rdx, 10h
	; if finished, go to end
	jz  aes_done
	; do next block
	jmp aes_loop
	; under 0x10
aes_under_loop:
	; lowest ctr byte
	pextrb rax, xmm3, 0
	; shift right one byte
	psrldq xmm3, 1
	; xor with byte
	xor    [rcx], al
	; data++, length--
	inc    rcx
	dec    rdx
	; keep going if not finished
	jnz    aes_under_loop
aes_done:
	ret
AesCtrCrypt endp

end