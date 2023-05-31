#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Not using assert(size == 1) because it creates new
  // basic blacks
  unsigned int byte0 = data[0];
  unsigned int byte1 = data[1];
  // to avoid unused variable compilation warnings
  (void)size;
  
  printf("[%d,%d] is input\n", byte0, byte1);
  
  if (byte0 > 3 && byte1 < 4) {
    printf("Took true direction!\n");
  } else {
    printf("Took false direction!\n");
  }

  return 0;
}