#ifndef EVENT_H_INCLUDED
#define EVENT_H_INCLUDED

#define MAX_COMMAND 256

enum Type
{
    Type_execve,
    Type_exit,
};

struct event
{
    enum Type type;
    int pid;
    int ppid;
    char command[MAX_COMMAND];
};

unsigned long hash_value(const char * c)
{
    const unsigned long p = 31;
    unsigned long hash_value = 0;
    unsigned long p_pow = 1;
    for (int n = 0; n < 256; ++n) {
        if (c[n] == '\0')
            break;
        hash_value += (c[n] - 'a' + 1) * p_pow;
        p_pow *= p;
    }
    const unsigned long m = 10e9 + 9;
    return hash_value % m;
}

#endif
