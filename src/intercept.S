.global func_hook_start
.global func_hook_end

func_hook_start:
	movq $0x1122334455667788, %rax
	call *%rax
func_hook_end:
	int3
	int3
	int3

