all:
	gcc -o valdemir_chaves_t2_b1_hash valdemir_chaves_t2_b1_hash.c -lssl -lcrypto
clean:
	rm -vf valdemir_chaves_t2_b1_hash