#include "simple.skel.h"

int main() {
    simple * skeleton = simple__open();
    simple__load(skeleton);
    simple__attach(skeleton);

    bool exiting = false;
    while (!exiting)
        sleep(1);

    simple__destroy(skel);
}
