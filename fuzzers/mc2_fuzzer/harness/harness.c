#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Not using assert(size == 1) because it creates new
  // basic blacks
  unsigned int byte0 = data[0];
  // to avoid unused variable compilation warnings
  (void)size;
  
  printf("%d is input\n", byte0);
  
  if (byte0 > 42 && byte0 < 54) {
    if(byte0 > 45){
      printf("Took true -> true direction!\n");
    }else{
      printf("Took true -> false direction!\n");
    }
  } else {
    printf("Took false direction!\n");
  }

  return 0;
}