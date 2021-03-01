#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int rsa_encrypt(RSA*, FILE*, FILE*);
int rsa_decrypt(RSA*, FILE*, FILE*);

int main(void) {
    RSA* private_key = NULL;
    RSA* public_key = NULL;
    FILE *fp, *fpin, *fpout;

    // FETCH KEY PAIR ///////////////////////////////////
    fp = fopen("key.pem", "r");
    PEM_read_RSAPrivateKey(fp, &private_key, NULL, NULL);
    fclose(fp);

    fp = fopen("pubkey.pem", "r");
    PEM_read_RSA_PUBKEY(fp, &public_key, NULL, NULL);
    fclose(fp);
    /////////////////////////////////////////////////////

    // Print key sizes, thus verifying their successful read
    printf("Private key size = %d\n", RSA_bits(private_key));
    printf("Public key size = %d\n", RSA_bits(public_key));

    // RSA ENCRYPTION //////////////////////////
    fpin = fopen("message.txt", "r");
    fpout = fopen("encrypted_message.txt", "w");
    rsa_encrypt(public_key, fpin, fpout);
    fclose(fpin);
    fclose(fpout);
    ////////////////////////////////////////////

    // RSA DECRYPTION //////////////////////////
    fpin = fopen("encrypted_message.txt", "r");
    fpout = fopen("decrypted_message.txt", "w");
    rsa_decrypt(private_key, fpin, fpout);
    fclose(fpin);
    fclose(fpout);
    ////////////////////////////////////////////

    return 0;
}

int rsa_encrypt(RSA* public_key, FILE* infile, FILE* outfile) {
    int key_size = RSA_size(public_key);
    char *buf, *encbuf;
    size_t len;

    // Quoting from man page of RSA_PUBLIC_ENCRYPT(3):
    // "flen must not be more than RSA_size(rsa) - 42 for RSA_PKCS1_OAEP_PADDING"
    buf = malloc(key_size - 42);
    // Encrypted block with padding will be `key_size' bytes long
    encbuf = malloc(key_size);

    do {
        // Read blocks of data from `infile' and encrypt them and write them out to `outfile', one block at a time.
        // Each block is at most (`key_size' - 42) bytes long. Do this in a loop until eof(infile) is encountered.

        // Quoting from man page of FREAD(3):
        // "If the end of the file is reached, the return value is a short item count (or zero)"
        // Hence, if 0 bytes were read, that's definitely an EOF, implying that we must stop
        if (!(len = fread(buf, 1, key_size - 42, infile))) break;
        printf("%u bytes read for encryption\n", len);

        if ((len = RSA_public_encrypt(len, buf, encbuf, public_key, RSA_PKCS1_OAEP_PADDING)) != key_size) {
            ERR_print_errors_fp(stderr);
            free(buf);
            free(encbuf);
            return -1;
        }
        printf("%u bytes encrypted\n", len);

        // Write it to outfile
        len = fwrite(encbuf, 1, len, outfile);
        printf("%u bytes written\n", len);

    } while (!feof(infile));

    free(buf);
    free(encbuf);

    return 0;
}

int rsa_decrypt(RSA* private_key, FILE* infile, FILE* outfile) {
    int key_size = RSA_size(private_key);
    char *buf, *decbuf;
    size_t len;

    // Encrypted blocks come in `key_size' bytes each
    buf = malloc(key_size);
    // Refer to this part of `rsa_encrypt()'.
    // Each block of `key_size' bytes will be decrypted to (`key_size' - 42) bytes.
    decbuf = malloc(key_size - 42);

    do {
        // Read blocks of data, each `key_size' bytes long, from `infile' and decrypt them and write them out to
        // `outfile', one block at a time. Each decrypted block is at most (`keysize' - 42) bytes long.
        // Do this in a loop until eof(infile) is encountered.

        // Quoting from man page of FREAD(3):
        // "If the end of the file is reached, the return value is a short item count (or zero)"
        // Hence, if 0 bytes were read, that's definitely an EOF, implying that we must stop
        if (!(len = fread(buf, 1, key_size, infile))) break;
        printf("%u bytes read for decryption\n", len);

        if ((len = RSA_private_decrypt(len, buf, decbuf, private_key, RSA_PKCS1_OAEP_PADDING)) == -1) {
            ERR_print_errors_fp(stderr);
            free(buf);
            free(decbuf);
            return -1;
        }
        printf("%u bytes decrypted\n", len);

        // Write it to outfile
        len = fwrite(decbuf, 1, len, outfile);
        printf("%u bytes written\n", len);

    } while (!feof(infile));

    free(buf);
    free(decbuf);

    return 0;
}
