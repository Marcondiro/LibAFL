all:
	@echo "make [clean, build]"

clean:
	rm -rf harness.so build *.o

build:
	mkdir -p build && cd build && cmake .. && make
	clang-11 -shared -Xclang -load -Xclang build/skeleton/libSkeletonPass.so -g3 -O0 harness.c -o harness.so 
