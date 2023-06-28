#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t byte0 = data[0];  // 1 byte

  // to avoid unused variable compilation warnings
  (void)size;

  printf("%d is input\n", byte0);

  int sum = 0;
  if (byte0 < 250) {
    sum = byte0 + 0;
    printf("Took true direction: %d is the result\n", sum);
  } else {
    sum = byte0 - 15;
    printf("Took false direction: %d is the result\n", sum);
  }

  return 0;
}