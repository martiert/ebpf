#ifndef EVENT_H_INCLUDED
#define EVENT_H_INCLUDED

#define MAX_COMMAND 256

struct event
{
    int pid;
    int ppid;
    char command[MAX_COMMAND];
};

#endif
