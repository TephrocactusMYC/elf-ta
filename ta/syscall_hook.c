#include "syscall.h"
#include "syscall_hook.h"

long syscall_hook0(long n) {
    return syscall_hook_impl(n, 0, 0, 0, 0, 0, 0);
}

long syscall_hook1(long n, long a) {
    return syscall_hook_impl(n, a, 0, 0, 0, 0, 0);
}

long syscall_hook2(long n, long a, long b) {
    return syscall_hook_impl(n, a, b, 0, 0, 0, 0);
}

long syscall_hook3(long n, long a, long b, long c) {
    return syscall_hook_impl(n, a, b, c, 0, 0, 0);
}

long syscall_hook4(long n, long a, long b, long c, long d) {
    return syscall_hook_impl(n, a, b, c, d, 0, 0);
}

long syscall_hook5(long n, long a, long b, long c, long d, long e) {
    return syscall_hook_impl(n, a, b, c, d, e, 0);
}

long syscall_hook6(long n, long a, long b, long c, long d, long e, long f) {
    return syscall_hook_impl(n, a, b, c, d, e, f);
}

