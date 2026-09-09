.text
.globl flag_chain
.type flag_chain,@function
flag_chain:
  endbr64
  mov %rsi, %rax
  mov %rdx, %r8
  mov $-1, %r9
  add $1, %r9
.Lflags:
  adc $0, %r8
  mov %r8, (%rdi)
  lea 8(%rdi), %rdi
  shl %cl, %r9
  dec %rsi
  jnz .Lflags
  ret
.size flag_chain, .-flag_chain

.globl aligned_copy
.type aligned_copy,@function
aligned_copy:
  endbr64
  mov %rsi, %rax
  mov 8(%rdx), %r8
  movdqa 16(%rdx), %xmm0
.Laligned:
  movdqa %xmm0, (%rdi)
  lea 16(%rdi), %rdi
  dec %rsi
  jnz .Laligned
  ret
.size aligned_copy, .-aligned_copy
.section .note.GNU-stack,"",@progbits
