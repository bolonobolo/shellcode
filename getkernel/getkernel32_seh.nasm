global _start


section .text
_start: 

	; raise the chain since we load the kernel32.dll address in eax
	push ecx
	push esi
	xor ecx, ecx
	mov esi, [fs:ecx]			; grab the first entry in the SEH list and store it in eax
	not ecx
loop:
	lodsd						; Next page
	mov esi, eax
	cmp [eax], ecx				; Compare the value at eax to see if its set to 0xffffffff. 
								; If it is, the last entry in the list has been reached 
								; and it’s function pointer should be inside kernel32.dll

	jne loop
	mov eax, [eax + 0x04]		; If the next entry in the list was equal to 0xffffffff, 
								; one knows the end has been hit. As such one can extract 
								; the function pointer for this entry and store it in eax.
loop2:	
	dec eax 					; Decrement eax. If the previous value was aligned to a 64KB boundary,
								; this will set us the low 16 bits of eax to 0xffff. If this is not the case it will
								; simply decrement eax to an undetermined value
	xor ax, ax					; Zero the low 16 bits of eax to align the address on a 64KB boundary
	cmp word [eax], 0x5a4d		; check to see if the 2 byte value at eax is ’MZ’
	jne loop2
	pop esi
	pop ecx
	ret