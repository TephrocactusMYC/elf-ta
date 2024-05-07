#ifndef SYSCALL_HOOK_H
#define SYSCALL_HOOK_H

long syscall_hook0(long n);

long syscall_hook1(long n, long a);

long syscall_hook2(long n, long a, long b);

long syscall_hook3(long n, long a, long b, long c);

long syscall_hook4(long n, long a, long b, long c, long d);

long syscall_hook5(long n, long a, long b, long c, long d, long e);

long syscall_hook6(long n, long a, long b, long c, long d, long e, long f);

#endif //SYSCALL_HOOK_H
