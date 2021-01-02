Base  equ 811c9dc5h
Prime equ 1000193h

.code
; calulate fnv-1a hash
; rcx: data, rdx: length
CalcFnv1aHash proc
	; continue with previous seed if eax not 0
	test eax, eax
	jnz  hash_loop
	;
	mov  eax, Base
hash_loop:
	xor  al,  [rcx]
	imul eax, Prime
	inc  rcx
	dec  rdx
	jnz  hash_loop
	ret
CalcFnv1aHash endp

end