#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t arg0 = data[0];                 // 1 byte
  float   arg1 = *((float *)(data + 1));  // 4 bytes
  uint8_t arg2 = data[5];                 // 1 byte

  // to avoid unused variable compilation warnings
  (void)size;

  printf("Hello from harness, I've received: [%u,%f, %d]\n", arg0, arg1, arg2);

  if (arg0 > 210) {
    printf("[0] Took true direction!\n");
    if (arg1 > 123.456) {
      printf("[1] Took true direction!\n");
      switch (arg2) {
        case 42:
          printf("[2] Took 42 direction!\n");
          break;
        default:
          printf("[2] Took default direction!\n");
      }
    } else {
      printf("[1] Took false direction!\n");
    }
  } else {
    printf("[0] Took false direction!\n");
  }

  return 0;
}