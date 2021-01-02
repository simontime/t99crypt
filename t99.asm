; console i/o
extern GetStdHandle:proc
extern ReadConsoleA:proc
extern WriteConsoleA:proc

; file i/o
extern CreateFileA:proc
extern ReadFile:proc
extern WriteFile:proc
extern GetFileSize:proc
extern CloseHandle:proc

; memory allocation
extern GlobalAlloc:proc
extern GlobalFree:proc

; crypto/hashing
extern AesCtrInit:proc
extern AesCtrCrypt:proc
extern CalcFnv1aHash:proc

; maximum filename length
MAX_PATH equ 260

; console i/o constants
STD_INPUT_HANDLE  equ -10
STD_OUTPUT_HANDLE equ -11

; file permissions
GENERIC_READ  equ 80000000h
GENERIC_WRITE equ 40000000h

; file open mode
CREATE_ALWAYS equ 2
OPEN_EXISTING equ 3

; file attribute
FILE_ATTRIBUTE_NORMAL equ 80h

; invalid handle value
INVALID_HANDLE_VALUE equ -1

S_SaveHeader struct
	version dd      ?
	hash    dd      ?
	key     xmmword ?
S_SaveHeader ends

.const
; strings
Str_SelectOpen db 'Input save file:',  0
Str_SelectSave db 'Output save file:', 0
Str_ErrorOpen  db 'Error opening input file.', 13, 10, 0
Str_ErrorSave  db 'Error opening output file.', 13, 10, 0
Str_ErrorHash  db 'Error: Invalid hash.', 13, 10, 0
Str_Complete   db 'Successfully decrypted save file!', 13, 10, 0
Str_End        db ?

; tetris 99 constant iv
AES_IV db 0fah, 03ch, 0ffh, 061h, 034h, 0beh, 0fdh, 009h, 000h, 07dh, 012h, 0ceh, 00ah, 082h, 0dfh, 010h

.code
Main proc
	local Temp:dd
	local ConsoleIn:dq, ConsoleOut:dq
	local HandleIn:dq, HandleOut:dq
	local SaveHeader:S_SaveHeader
	local Data:dq, DataLength:dq
	local OpenFileName[MAX_PATH]:db, SaveFileName[MAX_PATH]:db
	
	; store in handle
	mov  rcx, STD_INPUT_HANDLE
	call GetStdHandle
	mov  ConsoleIn, rax
	; store out handle
	mov  rcx, STD_OUTPUT_HANDLE
	call GetStdHandle
	mov  ConsoleOut, rax
	; print open filename prompt
	mov  rcx, ConsoleOut
	mov  rdx, offset Str_SelectOpen
	mov  r8,  Str_SelectSave-Str_SelectOpen
	mov  r9,  0
	push 0
	sub  rsp, 32
	call WriteConsoleA
	add  rsp, 32 + 8
	; read filename
	mov  rcx, ConsoleIn
	lea  rdx, OpenFileName
	mov  r8,  sizeof OpenFileName
	lea  r9,  DataLength
	push 0
	sub  rsp, 32
	call ReadConsoleA
	add  rsp, 32 + 8
	; null-terminate (remove \r\n)
	mov  rax, DataLength
	mov  word ptr [OpenFileName + rax - 2], 0
	; open input file
	lea  rcx, OpenFileName
	mov  rdx, GENERIC_READ
	xor  r8,  r8
	xor  r9,  r9
	push 0
	push FILE_ATTRIBUTE_NORMAL
	push OPEN_EXISTING
	sub  rsp, 32
	call CreateFileA
	add  rsp, 32 + 24
	; check if opened correctly
	cmp  rax, INVALID_HANDLE_VALUE
	jne  store_in
	mov  rdx, offset Str_ErrorOpen
	mov  r8,  Str_ErrorSave-Str_ErrorOpen
	jmp _error
	; store in handle
store_in:
	mov  HandleIn, rax
	; print save filename prompt
	mov  rcx, ConsoleOut
	mov  rdx, offset Str_SelectSave
	mov  r8,  Str_ErrorOpen-Str_SelectSave
	xor  r9,  r9
	push 0
	sub  rsp, 32
	call WriteConsoleA
	add  rsp, 32 + 8
	; read filename
	mov  rcx, ConsoleIn
	lea  rdx, SaveFileName
	mov  r8,  sizeof SaveFileName
	lea  r9,  DataLength
	push 0
	sub  rsp, 32
	call ReadConsoleA
	add  rsp, 32 + 8
	; null-terminate (remove \r\n)
	mov  rax, DataLength
	mov  word ptr [SaveFileName + rax - 2], 0
	; open output file
	lea  rcx, SaveFileName
	mov  rdx, GENERIC_WRITE
	xor  r8,  r8
	xor  r9,  r9
	push 0
	push FILE_ATTRIBUTE_NORMAL
	push CREATE_ALWAYS
	sub  rsp, 32
	call CreateFileA
	add  rsp, 32 + 24
	; check if opened correctly
	cmp  rax, INVALID_HANDLE_VALUE
	jne  store_out
	mov  rdx, offset Str_ErrorSave
	mov  r8,  Str_ErrorHash-Str_ErrorSave
	jmp _error
store_out:
	; store out handle
	mov  HandleOut, rax
	; get file size
	mov  rcx, HandleIn
	xor  rdx, rdx
	call GetFileSize
	sub  rax, sizeof S_SaveHeader
	mov  DataLength, rax
	; allocate memory
	xor  rcx, rcx
	mov  rdx, DataLength
	call GlobalAlloc
	mov  Data, rax
	; read header
	mov  rcx, HandleIn
	lea  rdx, SaveHeader
	mov  r8d, sizeof S_SaveHeader
	lea  r9,  Temp
	push 0
	sub  rsp, 32
	call ReadFile
	add  rsp, 32 + 8
	; read data
	mov  rcx, HandleIn
	mov  rdx, Data
	mov  r8,  DataLength
	lea  r9,  Temp
	push 0
	sub  rsp, 32
	call ReadFile
	add  rsp, 32 + 8
	; close input
	mov  rcx, HandleIn
	call CloseHandle
	; preserve hash and clear
	mov  r8d, SaveHeader.hash
	mov  SaveHeader.hash, 0
	; calculate hash
	xor  eax, eax
	lea  rcx, SaveHeader
	mov  rdx, sizeof S_SaveHeader
	call CalcFnv1aHash
	mov  rcx, Data
	mov  rdx, DataLength
	call CalcFnv1aHash
	; ensure match
	cmp  eax, r8d
	je   decrypt
	mov  rdx, offset Str_ErrorHash
	mov  r8,  Str_Complete-Str_ErrorHash
	jmp _error
decrypt:
	; initialise decryptor
	movdqu xmm0, SaveHeader.key
	movdqu xmm3, xmmword ptr AES_IV
	call AesCtrInit
	; decrypt data
	mov  rcx, Data
	mov  rdx, DataLength
	call AesCtrCrypt
	; write decrypted data
	mov  rcx, HandleOut
	mov  rdx, Data
	mov  r8,  DataLength
	lea  r9,  Temp
	push 0
	sub  rsp, 32
	call WriteFile
	add  rsp, 32 + 8
	; close output
	mov  rcx, HandleOut
	call CloseHandle
	; free memory
	mov  rcx, Data
	call GlobalFree
	; print completion message
	mov  rdx, offset Str_Complete
	mov  r8,  Str_End-Str_Complete
_error:
	mov  rcx, ConsoleOut
	xor  r9,  r9
	push 0
	sub  rsp, 32
	call WriteConsoleA
	add  rsp, 32 + 8
	ret
Main endp

end