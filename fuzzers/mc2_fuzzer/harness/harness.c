#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // TODO for which obscure reason does this fail? Rust - C data types are
  // different?
  //   assert(size == 1LU);
  unsigned int byte0 = data[0];

  printf("%d is input\n", byte0);

  int sum = 0;
  if (byte0 < 3) {
    sum = byte0 + 0;
    printf("Took true direction: %d is the result\n", sum);
  } else {
    sum = byte0 - 15;
    printf("Took false direction: %d is the result\n", sum);
  }

  return 0;
}