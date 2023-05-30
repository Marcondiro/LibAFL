# MC2 Fuzzer

# Example 1 (TODO)

## Description

This is the very initial function that has been used to develop the fuzzer, it is very simple as it has only one branch instruction:

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Not using assert(size == 1) because it creates new
  // basic blacks, we want this function to have only
  // three basic block
  unsigned int byte0 = data[0];
  // to avoid unused variable compilation warnings
  (void)size;

  printf("%d is input\n", byte0);

  if (byte0 < 3) {
    printf("Took true direction!\n");
  } else {
    printf("Took false direction!\n");
  }

  return 0;
}
```

In order to target a specific basic block we need to identify the br_id and the direction.
The output of the instrumentation can be used to ease this process:

```
@@@ LLVMFuzzerTestOneInput, branch id: 0| loc ./harness/harness.c:16
@@@ LLVMFuzzerTestOneInput, branch id: 1| loc ./harness/harness.c:18
@@@ LLVMFuzzerTestOneInput, branch id: 2| loc UNKNOWN
@@@ LLVMFuzzerTestOneInput, branch id: 3| loc ./harness/harness.c:22
@@@ edge id (0,1), cond type ICMP_ULT, true
@@@ edge id (0,2), cond type ICMP_UGE, false
```

Here it's very easy, since there are only three basic block, we just need to chose the direction of the only branch `br_id = 0`.
Thus we write in the `branch_policy.txt` the line `0 true` .

# Example 2 (TODO)

The following function is more complex than the previous one because here we have three branch instruction:

- `byte0 > 42`
- `byte0 < 54`
- `byte0 > 45`

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Not using assert(size == 1) because it creates new
  // basic blocks
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
```

Instrumentation output:

```
@@@ LLVMFuzzerTestOneInput, branch id: 0| loc ./harness/harness.c:16
@@@ LLVMFuzzerTestOneInput, branch id: 1| loc ./harness/harness.c:16
@@@ LLVMFuzzerTestOneInput, branch id: 2| loc ./harness/harness.c:18
@@@ LLVMFuzzerTestOneInput, branch id: 3| loc UNKNOWN
@@@ LLVMFuzzerTestOneInput, branch id: 4| loc ./harness/harness.c:22
@@@ edge id (0,1), cond type ICMP_UGT, true
@@@ edge id (0,3), cond type ICMP_ULE, false
@@@ edge id (1,2), cond type ICMP_ULT, true
@@@ edge id (1,3), cond type ICMP_UGE, false

```

branch_policy.txt
0,true
0,true
0,true
