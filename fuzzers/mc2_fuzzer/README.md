# MC2 Fuzzer

Porting in Rust of the fuzzer MC2 proposed inn the paper _MC2: Rigorous and Efficient Directed Greybox Fuzzing_, more details available [in this blog post from the author](https://www.cs.columbia.edu/~ass/post/mc2/).
At the moment the fuzzer works only on simple toy programs.

## Example

This is the very initial function that has been used to develop the fuzzer, it is very simple as it has only one branch instruction:

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
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
The output of the instrumentation `branches.txt` can be used to ease this process:

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
