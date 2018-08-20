#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define UNPACK(u32) \
    (uint8_t)(u32 >> 24), \
    (uint8_t)(u32 >> 16), \
    (uint8_t)(u32 >> 8), \
    (uint8_t)(u32)

#define FORMAT "{{%u, %u, %u, %u}, %s},"

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("eg. 0.0.0.0-0.255.255.255\n");
        return -1;
    }
    printf("\n");
    printf("// %s\n", argv[1]);
    char *pstart = strtok(argv[1], "-");
    //puts(start);
    char *pend = strtok(NULL, "-");
    //puts(end);

    uint8_t b0 = (uint8_t)atoi(strtok(pstart, "."));
    uint8_t b1 = (uint8_t)atoi(strtok(NULL, "."));
    uint8_t b2 = (uint8_t)atoi(strtok(NULL, "."));
    uint8_t b3 = (uint8_t)atoi(strtok(NULL, "."));
    uint32_t start = b0 << 24 | b1 << 16 | b2 << 8 | b3;

    b0 = (uint8_t)atoi(strtok(pend, "."));
    b1 = (uint8_t)atoi(strtok(NULL, "."));
    b2 = (uint8_t)atoi(strtok(NULL, "."));
    b3 = (uint8_t)atoi(strtok(NULL, "."));
    uint32_t end = b0 << 24 | b1 << 16 | b2 << 8 | b3;

    if (start == 0xffffffff) {
        printf(FORMAT "\n", UNPACK(start), "false");
        return 0;
    }

    if (start && start - 1 && start - 2) {
        printf(FORMAT " // start-2\n", UNPACK(start - 2), "true");
        printf(FORMAT " // start-1\n", UNPACK(start - 1), "true");
    }
    printf(FORMAT " // start\n", UNPACK(start), "false");
    printf(FORMAT " // start+1\n", UNPACK(start + 1), "false");
    printf(FORMAT " // end-1\n", UNPACK(end - 1), "false");
    printf(FORMAT " // end\n", UNPACK(end), "false");
    if (end != 0xffffffff && end + 1 != 0xffffffff && end + 2 != 0xffffffff) {
        printf(FORMAT " // end+1\n", UNPACK(end + 1), "true");
        printf(FORMAT " // end+2\n", UNPACK(end + 2), "true");
    }
    return 0;
}
