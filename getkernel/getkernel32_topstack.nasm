find_kernel32:
	push esi
	xor  esi, esi
	mov  esi, [fs:esi + 0x18]
	lodsd
	lodsd
	mov  eax, [eax - 0x1c]
find_kernel32_base:
	find_kernel32_base_loop:
		dec  eax
		xor  ax, ax
		cmp  word [eax], 0x5a4d
		jne  find_kernel32_base_loop
	find_kernel32_base_finished:
		pop  esi
		ret