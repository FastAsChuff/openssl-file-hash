# openssl-file-hash
Uses openssl to calculate a hash of a file without loading more than 16KiB into memory at a time.

Openssl uses SHA instruction set extensions on modern x86_64 cpus to accelerate calculations of SHA1 and SHA256 hashes.

To use a different hash, change the name in OSSL_HASH_DIGEST_NAME. 

Also set the appropriate value for OSSL_HASH_DIGEST_LEN which should be half the number of hex digits in the hash output.

e.g. 

#define OSSL_HASH_DIGEST_NAME "SHA256"

#define OSSL_HASH_DIGEST_LEN 32

e.g. 

#define OSSL_HASH_DIGEST_NAME "SHA512"

#define OSSL_HASH_DIGEST_LEN 64
