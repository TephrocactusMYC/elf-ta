#ifndef ELF_UTIL_H
#define ELF_UTIL_H

#define round_up(x, y) ((((x) + (y) - 1) / (y)) * (y))
#define round_down(x, y) ((x) - ((x) % (y)))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

#endif //ELF_UTIL_H
