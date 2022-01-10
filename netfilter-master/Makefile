all: netfilter_test

netfilter_test: av.c
	gcc -o netfilter_test av.c -lnetfilter_queue

clean:
	rm netfilter_test
