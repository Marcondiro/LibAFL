# MC2 Fuzzer

### libxml2 compilation

installo go

```sh
wget https://dl.google.com/go/go1.20.5.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.20.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

INSTALLATION OF GLLVM

```sh
# export GOPATH=/root/go
export GOPATH=/go
GO111MODULE=off go get github.com/SRI-CSL/gllvm/cmd/...
export PATH=${GOPATH}/bin:${PATH}

```

Download libxml2

```sh
git clone https://github.com/GNOME/libxml2.git
cd libxml2
```

Then inside the `lilbxml2/fuzz` folder, add a file main.c containing the following:

```c
int __attribute__((weak)) main() { return 0; }
```

Back to `libxml2/` run:

```sh
WLLVM_CONFIGURE_ONLY=1 CC=gclang CFLAGS='-g -O0' ./autogen.sh \
    --disable-shared \
    --without-debug \
    --without-ftp \
    --without-http \
    --without-legacy \
    --without-python

cd fuzz
make clean-corpus
make fuzz.o
make xml.o

gclang -c main.c

gclang++ -g -O0 xml.o fuzz.o main.o -o harness ../.libs/libxml2.a -Wl,-Bstatic -lz -llzma -Wl,-Bdynamic

get-bc -o harness.bc harness

```

## Example 1 (TODO)

### Description

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

## Example 2 (TODO)

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
