.global ___dlopen_stub

___dlopen_stub:
	push %rdi
	push %rbx
	push %rsi
	call last
next:
	pop %rbx
	mov %rbx, %rdi
	add $8, %rdi
#RTLD_NOW
	mov $2, %rsi
	mov (%rbx), %rbx
#	int3
	call *%rbx

	pop %rbx
	pop %rsi
	pop %rbx
	pop %rdi

	ret
last:
	call next
	
data:
	.quad 0xdeadbeefdeadbeef
	.asciz "/home/shw/gotrace/gldtest/crap.so"
