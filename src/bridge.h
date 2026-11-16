#ifndef CONVEYOR_BRIDGE_H
#define CONVEYOR_BRIDGE_H
#include <linux/types.h>
struct bridge_config {
    __u32 upstream;
    __u32 downstream;
    __u32 mirror;
};
#endif
