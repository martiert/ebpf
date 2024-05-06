#ifndef EVENT_H_INCLUDED
#define EVENT_H_INCLUDED

#define TASK_COMM_LEN 128

struct event
{
    int pid;
    int ppid;
    char comm[TASK_COMM_LEN];
};

#endif
