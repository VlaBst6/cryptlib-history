	; Don't even think of reading this code
	; It was automatically generated by cast-586.pl
	; Which is a perl program used to generate the x86 assember for
	; any of elf, a.out, BSDI, Win32, gaswin (for GNU as on Win32) or Solaris
	; eric <eay@cryptsoft.com>
	; 
segment .text
extern	_CAST_S_table0
extern	_CAST_S_table1
extern	_CAST_S_table2
extern	_CAST_S_table3
global	_CAST_encrypt
_CAST_encrypt:
	; 
	push	ebp
	push	ebx
	mov	ebx,		[12+esp]
	mov	ebp,		[16+esp]
	push	esi
	push	edi
	; Load the 2 words
	mov	edi,		[ebx]
	mov	esi,		[4+ebx]
	; Get short key flag
	mov	eax,		[128+ebp]
	push	eax
	xor	eax,		eax
	; round 0
	mov	edx,		[ebp]
	mov	ecx,		[4+ebp]
	add	edx,		esi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	xor	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	sub	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	add	ecx,		ebx
	xor	edi,		ecx
	; round 1
	mov	edx,		[8+ebp]
	mov	ecx,		[12+ebp]
	xor	edx,		edi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	sub	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	add	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	xor	ecx,		ebx
	xor	esi,		ecx
	; round 2
	mov	edx,		[16+ebp]
	mov	ecx,		[20+ebp]
	sub	edx,		esi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	add	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	xor	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	sub	ecx,		ebx
	xor	edi,		ecx
	; round 3
	mov	edx,		[24+ebp]
	mov	ecx,		[28+ebp]
	add	edx,		edi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	xor	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	sub	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	add	ecx,		ebx
	xor	esi,		ecx
	; round 4
	mov	edx,		[32+ebp]
	mov	ecx,		[36+ebp]
	xor	edx,		esi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	sub	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	add	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	xor	ecx,		ebx
	xor	edi,		ecx
	; round 5
	mov	edx,		[40+ebp]
	mov	ecx,		[44+ebp]
	sub	edx,		edi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	add	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	xor	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	sub	ecx,		ebx
	xor	esi,		ecx
	; round 6
	mov	edx,		[48+ebp]
	mov	ecx,		[52+ebp]
	add	edx,		esi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	xor	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	sub	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	add	ecx,		ebx
	xor	edi,		ecx
	; round 7
	mov	edx,		[56+ebp]
	mov	ecx,		[60+ebp]
	xor	edx,		edi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	sub	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	add	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	xor	ecx,		ebx
	xor	esi,		ecx
	; round 8
	mov	edx,		[64+ebp]
	mov	ecx,		[68+ebp]
	sub	edx,		esi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	add	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	xor	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	sub	ecx,		ebx
	xor	edi,		ecx
	; round 9
	mov	edx,		[72+ebp]
	mov	ecx,		[76+ebp]
	add	edx,		edi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	xor	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	sub	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	add	ecx,		ebx
	xor	esi,		ecx
	; round 10
	mov	edx,		[80+ebp]
	mov	ecx,		[84+ebp]
	xor	edx,		esi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	sub	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	add	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	xor	ecx,		ebx
	xor	edi,		ecx
	; round 11
	mov	edx,		[88+ebp]
	mov	ecx,		[92+ebp]
	sub	edx,		edi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	add	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	xor	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	sub	ecx,		ebx
	xor	esi,		ecx
	; test short key flag
	pop	edx
	or	edx,		edx
	jnz NEAR	$L000cast_enc_done
	; round 12
	mov	edx,		[96+ebp]
	mov	ecx,		[100+ebp]
	add	edx,		esi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	xor	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	sub	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	add	ecx,		ebx
	xor	edi,		ecx
	; round 13
	mov	edx,		[104+ebp]
	mov	ecx,		[108+ebp]
	xor	edx,		edi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	sub	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	add	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	xor	ecx,		ebx
	xor	esi,		ecx
	; round 14
	mov	edx,		[112+ebp]
	mov	ecx,		[116+ebp]
	sub	edx,		esi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	add	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	xor	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	sub	ecx,		ebx
	xor	edi,		ecx
	; round 15
	mov	edx,		[120+ebp]
	mov	ecx,		[124+ebp]
	add	edx,		edi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	xor	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	sub	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	add	ecx,		ebx
	xor	esi,		ecx
$L000cast_enc_done:
	nop
	mov	eax,		[20+esp]
	mov	[4+eax],	edi
	mov	[eax],		esi
	pop	edi
	pop	esi
	pop	ebx
	pop	ebp
	ret
extern	_CAST_S_table0
extern	_CAST_S_table1
extern	_CAST_S_table2
extern	_CAST_S_table3
global	_CAST_decrypt
_CAST_decrypt:
	; 
	push	ebp
	push	ebx
	mov	ebx,		[12+esp]
	mov	ebp,		[16+esp]
	push	esi
	push	edi
	; Load the 2 words
	mov	edi,		[ebx]
	mov	esi,		[4+ebx]
	; Get short key flag
	mov	eax,		[128+ebp]
	or	eax,		eax
	jnz NEAR	$L001cast_dec_skip
	xor	eax,		eax
	; round 15
	mov	edx,		[120+ebp]
	mov	ecx,		[124+ebp]
	add	edx,		esi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	xor	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	sub	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	add	ecx,		ebx
	xor	edi,		ecx
	; round 14
	mov	edx,		[112+ebp]
	mov	ecx,		[116+ebp]
	sub	edx,		edi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	add	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	xor	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	sub	ecx,		ebx
	xor	esi,		ecx
	; round 13
	mov	edx,		[104+ebp]
	mov	ecx,		[108+ebp]
	xor	edx,		esi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	sub	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	add	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	xor	ecx,		ebx
	xor	edi,		ecx
	; round 12
	mov	edx,		[96+ebp]
	mov	ecx,		[100+ebp]
	add	edx,		edi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	xor	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	sub	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	add	ecx,		ebx
	xor	esi,		ecx
$L001cast_dec_skip:
	; round 11
	mov	edx,		[88+ebp]
	mov	ecx,		[92+ebp]
	sub	edx,		esi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	add	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	xor	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	sub	ecx,		ebx
	xor	edi,		ecx
	; round 10
	mov	edx,		[80+ebp]
	mov	ecx,		[84+ebp]
	xor	edx,		edi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	sub	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	add	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	xor	ecx,		ebx
	xor	esi,		ecx
	; round 9
	mov	edx,		[72+ebp]
	mov	ecx,		[76+ebp]
	add	edx,		esi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	xor	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	sub	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	add	ecx,		ebx
	xor	edi,		ecx
	; round 8
	mov	edx,		[64+ebp]
	mov	ecx,		[68+ebp]
	sub	edx,		edi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	add	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	xor	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	sub	ecx,		ebx
	xor	esi,		ecx
	; round 7
	mov	edx,		[56+ebp]
	mov	ecx,		[60+ebp]
	xor	edx,		esi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	sub	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	add	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	xor	ecx,		ebx
	xor	edi,		ecx
	; round 6
	mov	edx,		[48+ebp]
	mov	ecx,		[52+ebp]
	add	edx,		edi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	xor	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	sub	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	add	ecx,		ebx
	xor	esi,		ecx
	; round 5
	mov	edx,		[40+ebp]
	mov	ecx,		[44+ebp]
	sub	edx,		esi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	add	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	xor	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	sub	ecx,		ebx
	xor	edi,		ecx
	; round 4
	mov	edx,		[32+ebp]
	mov	ecx,		[36+ebp]
	xor	edx,		edi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	sub	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	add	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	xor	ecx,		ebx
	xor	esi,		ecx
	; round 3
	mov	edx,		[24+ebp]
	mov	ecx,		[28+ebp]
	add	edx,		esi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	xor	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	sub	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	add	ecx,		ebx
	xor	edi,		ecx
	; round 2
	mov	edx,		[16+ebp]
	mov	ecx,		[20+ebp]
	sub	edx,		edi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	add	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	xor	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	sub	ecx,		ebx
	xor	esi,		ecx
	; round 1
	mov	edx,		[8+ebp]
	mov	ecx,		[12+ebp]
	xor	edx,		esi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	sub	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	add	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	xor	ecx,		ebx
	xor	edi,		ecx
	; round 0
	mov	edx,		[ebp]
	mov	ecx,		[4+ebp]
	add	edx,		edi
	rol	edx,		cl
	mov	ebx,		edx
	xor	ecx,		ecx
	mov	cl,		dh
	and	ebx,		255
	shr	edx,		16
	xor	eax,		eax
	mov	al,		dh
	and	edx,		255
	mov	ecx,		[_CAST_S_table0+ecx*4]
	mov	ebx,		[_CAST_S_table1+ebx*4]
	xor	ecx,		ebx
	mov	ebx,		[_CAST_S_table2+eax*4]
	sub	ecx,		ebx
	mov	ebx,		[_CAST_S_table3+edx*4]
	add	ecx,		ebx
	xor	esi,		ecx
	nop
	mov	eax,		[20+esp]
	mov	[4+eax],	edi
	mov	[eax],		esi
	pop	edi
	pop	esi
	pop	ebx
	pop	ebp
	ret
global	_CAST_cbc_encrypt
_CAST_cbc_encrypt:
	; 
	push	ebp
	push	ebx
	push	esi
	push	edi
	mov	ebp,		[28+esp]
	; getting iv ptr from parameter 4
	mov	ebx,		[36+esp]
	mov	esi,		[ebx]
	mov	edi,		[4+ebx]
	push	edi
	push	esi
	push	edi
	push	esi
	mov	ebx,		esp
	mov	esi,		[36+esp]
	mov	edi,		[40+esp]
	; getting encrypt flag from parameter 5
	mov	ecx,		[56+esp]
	; get and push parameter 3
	mov	eax,		[48+esp]
	push	eax
	push	ebx
	cmp	ecx,		0
	jz NEAR	$L002decrypt
	and	ebp,		4294967288
	mov	eax,		[8+esp]
	mov	ebx,		[12+esp]
	jz NEAR	$L003encrypt_finish
L004encrypt_loop:
	mov	ecx,		[esi]
	mov	edx,		[4+esi]
	xor	eax,		ecx
	xor	ebx,		edx
	bswap	eax
	bswap	ebx
	mov	[8+esp],	eax
	mov	[12+esp],	ebx
	call	_CAST_encrypt
	mov	eax,		[8+esp]
	mov	ebx,		[12+esp]
	bswap	eax
	bswap	ebx
	mov	[edi],		eax
	mov	[4+edi],	ebx
	add	esi,		8
	add	edi,		8
	sub	ebp,		8
	jnz NEAR	L004encrypt_loop
$L003encrypt_finish:
	mov	ebp,		[52+esp]
	and	ebp,		7
	jz NEAR	$L005finish
	xor	ecx,		ecx
	xor	edx,		edx
	mov	ebp,		[$L006cbc_enc_jmp_table+ebp*4]
	jmp	 ebp
L007ej7:
	xor	edx,		edx
	mov	dh,		[6+esi]
	shl	edx,		8
L008ej6:
	mov	dh,		[5+esi]
L009ej5:
	mov	dl,		[4+esi]
L010ej4:
	mov	ecx,		[esi]
	jmp	$L011ejend
L012ej3:
	mov	ch,		[2+esi]
	xor	ecx,		ecx
	shl	ecx,		8
L013ej2:
	mov	ch,		[1+esi]
L014ej1:
	mov	cl,		[esi]
$L011ejend:
	xor	eax,		ecx
	xor	ebx,		edx
	bswap	eax
	bswap	ebx
	mov	[8+esp],	eax
	mov	[12+esp],	ebx
	call	_CAST_encrypt
	mov	eax,		[8+esp]
	mov	ebx,		[12+esp]
	bswap	eax
	bswap	ebx
	mov	[edi],		eax
	mov	[4+edi],	ebx
	jmp	$L005finish
$L002decrypt:
	and	ebp,		4294967288
	mov	eax,		[16+esp]
	mov	ebx,		[20+esp]
	jz NEAR	$L015decrypt_finish
L016decrypt_loop:
	mov	eax,		[esi]
	mov	ebx,		[4+esi]
	bswap	eax
	bswap	ebx
	mov	[8+esp],	eax
	mov	[12+esp],	ebx
	call	_CAST_decrypt
	mov	eax,		[8+esp]
	mov	ebx,		[12+esp]
	bswap	eax
	bswap	ebx
	mov	ecx,		[16+esp]
	mov	edx,		[20+esp]
	xor	ecx,		eax
	xor	edx,		ebx
	mov	eax,		[esi]
	mov	ebx,		[4+esi]
	mov	[edi],		ecx
	mov	[4+edi],	edx
	mov	[16+esp],	eax
	mov	[20+esp],	ebx
	add	esi,		8
	add	edi,		8
	sub	ebp,		8
	jnz NEAR	L016decrypt_loop
$L015decrypt_finish:
	mov	ebp,		[52+esp]
	and	ebp,		7
	jz NEAR	$L005finish
	mov	eax,		[esi]
	mov	ebx,		[4+esi]
	bswap	eax
	bswap	ebx
	mov	[8+esp],	eax
	mov	[12+esp],	ebx
	call	_CAST_decrypt
	mov	eax,		[8+esp]
	mov	ebx,		[12+esp]
	bswap	eax
	bswap	ebx
	mov	ecx,		[16+esp]
	mov	edx,		[20+esp]
	xor	ecx,		eax
	xor	edx,		ebx
	mov	eax,		[esi]
	mov	ebx,		[4+esi]
L017dj7:
	ror	edx,		16
	mov	[6+edi],	dl
	shr	edx,		16
L018dj6:
	mov	[5+edi],	dh
L019dj5:
	mov	[4+edi],	dl
L020dj4:
	mov	[edi],		ecx
	jmp	$L021djend
L022dj3:
	ror	ecx,		16
	mov	[2+edi],	cl
	shl	ecx,		16
L023dj2:
	mov	[1+esi],	ch
L024dj1:
	mov	[esi],		cl
$L021djend:
	jmp	$L005finish
$L005finish:
	mov	ecx,		[60+esp]
	add	esp,		24
	mov	[ecx],		eax
	mov	[4+ecx],	ebx
	pop	edi
	pop	esi
	pop	ebx
	pop	ebp
	ret
$L006cbc_enc_jmp_table:
	DD	0
	DD	L014ej1
	DD	L013ej2
	DD	L012ej3
	DD	L010ej4
	DD	L009ej5
	DD	L008ej6
	DD	L007ej7
L025cbc_dec_jmp_table:
	DD	0
	DD	L024dj1
	DD	L023dj2
	DD	L022dj3
	DD	L020dj4
	DD	L019dj5
	DD	L018dj6
	DD	L017dj7
