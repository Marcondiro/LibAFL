all:
	@echo "make [clean, build]"

clean:
	rm -rf harness.so build *.o

build:
	mkdir -p build && cd build && cmake .. && make
	# clang-11 -Xclang -load -Xclang build/skeleton/libSkeletonPass.so -g3 -c -O0 harness.c -o harness.o 
