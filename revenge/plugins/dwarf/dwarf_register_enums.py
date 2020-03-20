
# TODO: Put in enums for arm/arm64/etc
# Using the process.arch enum

_REG_NAMES = {
    'x64': [
	'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi',
	'eip', 'eflags', '<none>', 'st0', 'st1', 'st2', 'st3', 'st4',
	'st5', 'st6', 'st7', '<none>', '<none>', 'xmm0', 'xmm1', 'xmm2',
	'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7', 'mm0', 'mm1', 'mm2',
	'mm3', 'mm4', 'mm5', 'mm6', 'mm7', 'fcw', 'fsw', 'mxcsr',
	'es', 'cs', 'ss', 'ds', 'fs', 'gs', '<none>', '<none>', 'tr', 'ldtr'
    ],
    'ia32': [
	'rax', 'rdx', 'rcx', 'rbx', 'rsi', 'rdi', 'rbp', 'rsp',
	'r8',  'r9',  'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
	'rip', 'xmm0',  'xmm1',  'xmm2',  'xmm3', 'xmm4', 'xmm5', 'xmm6',
	'xmm7', 'xmm8', 'xmm9', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14',
	'xmm15', 'st0', 'st1', 'st2', 'st3', 'st4', 'st5', 'st6',
	'st7', 'mm0', 'mm1', 'mm2', 'mm3', 'mm4', 'mm5', 'mm6',
	'mm7', 'rflags', 'es', 'cs', 'ss', 'ds', 'fs', 'gs',
	'<none>', '<none>', 'fs.base', 'gs.base', '<none>', '<none>', 'tr', 'ldtr',
	'mxcsr', 'fcw', 'fsw'
    ],
}
