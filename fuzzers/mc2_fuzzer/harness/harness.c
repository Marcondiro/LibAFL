#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t arg0 = data[0];  // 1 byte
  float   arg1 = data[1];  // 1 byte
  uint8_t arg2 = data[2];  // 1 byte

  // to avoid unused variable compilation warnings
  (void)size;

  printf("Hello from harness, I've received: [%u,%f, %d]\n", arg0, arg1, arg2);

  if (arg0 > 210) {
    printf("[0] Took true direction!\n");
    if (arg1 < 13.123) {
      printf("[1] Took true direction!\n");
    } else {
      printf("[1] Took false direction!\n");
    }
  } else {
    printf("[0] Took false direction!\n");
  }

  return 0;
}