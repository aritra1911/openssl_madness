# RSA Encryption / Decryption
> You'll need to generate your own key pair in order to use this. A sample pair already exists in this repo in PEM
> format. Check `notes.txt` for instructions regarding command line operation of openssl and generating a key pair
> through the same. I've tested mostly using RSA 4096, but feel free to test other key sizes as well.

This is a test repo for me to get familiar with openssl and specifically the RSA part of the openssl API.

## Compile
You'll need a C compiler.
```sh
$ make
```

## Usage
```
Usage : ./madness [-i FILE] -k PEM_FILE -(e|d) [-o FILE] [-v]
RSA Encryption / Decryption Tool using OpenSSL API

    -h, --help        Show this help and exit

    -i, --infile      Specify file to be read for data. When omitted, stdin will be used by default.

    -k, --keyfile     Specify public / private key file in PEM format. If --decrypt flag is specified, the
                      specified key is treated as a private key, otherwise the same is treated as a public
                      key when --encrypt is specified.

    -o, --outfile     Specify file to write data to. When omitted, stdout will be used by default.

    -e, --encrypt     Specify encryption operation to be performed on the read data with value of --keyfile
                      treated as the public key.

    -d, --decrypt     Signify decryption operation to be performed on the read data with value of --keyfile
                      treated as the private key.

    -v, --verbose     Show RSA size, blocks of data read, encrypted / decrypted, written.
```

## References
1.  https://www.openssl.org/docs/man1.1.1/man3/
2.  Manpages:
    - OPENSSL(1)
    - GENRSA(1)
    - RSA(1)
    - RSAUTL(1)
    - RSA\_SIZE(3)
    - PEM\_READ\_BIO\_PRIVATEKEY(3)
    - RSA\_PUBLIC\_ENCRYPT(3)
    - ERR\_PRINT\_ERRORS(3)
    - FOPEN(3P)
    - FREAD(3P)
    - FWRITE(3P)
    - GETOPT(3)
    - ERRNO(3P)
    - STRERROR(3P)
3.  https://false.ekta.is/2011/08/openssl-pem\_read\_rsa\_pubkey-vs-pem\_read\_rsapublickey/
