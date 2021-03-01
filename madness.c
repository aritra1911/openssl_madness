#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define BUFFER_SIZE 512

int rsa_encrypt(RSA*, FILE*, FILE*);

int main(void) {
    RSA* private_key = NULL;
    RSA* public_key = NULL;
    FILE *fp, *fpin, *fpout;
    char buf[BUFFER_SIZE];
    size_t len;

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

    // Read encrypted file
    fp = fopen("encrypted_message.txt", "r");
    len = fread(buf, 1, RSA_size(private_key), fp);
    fclose(fp);
    printf("%u bytes read from `encrypted_message.txt'\n", len);

    // RSA DECRYPTION //////////////////////////////////////////////////////////////////////////
    char* decrypted_message = malloc(RSA_size(private_key));
    len = RSA_private_decrypt(len, buf, decrypted_message, private_key, RSA_PKCS1_OAEP_PADDING);
    //printf("%s\n", decrypted_message);
    printf("%u bytes decrypted\n", len);

    // Write it out to a file
    fp = fopen("decrypted_message.txt", "w");
    len = fwrite(decrypted_message, 1, len, fp);
    free(decrypted_message);
    fclose(fp);
    printf("%u bytes written to `decrypted_message.txt'\n", len);
    ////////////////////////////////////////////////////////////////////////////////////////////

    return 0;
}

int rsa_encrypt(RSA* public_key, FILE* infile, FILE* outfile) {
    int key_size = RSA_size(public_key);
    char *buf, *encbuf;
    size_t len;

    // Quoting from man page:
    // "flen must not be more than RSA_size(rsa) - 42 for RSA_PKCS1_OAEP_PADDING"
    buf = malloc(key_size - 42);
    // Encrypted block with padding will be `key_size' bytes long
    encbuf = malloc(key_size);

    do {
        // Read blocks of data from `infile' and encrypt them and write them out to `outfile', one block at a time.
        // Each block is at most (`key_size' - 42) bytes long. Do this in a loop until eof(infile) is encountered.

        len = fread(buf, 1, key_size - 42, infile);
        printf("%u bytes read\n", len);

        if ((len = RSA_public_encrypt(len, buf, encbuf, public_key, RSA_PKCS1_OAEP_PADDING)) != key_size) {
            ERR_print_errors_fp(stderr);
            free(buf);
            free(encbuf);
            return -1;
        }

        // Write it out to a file
        len = fwrite(encbuf, 1, len, outfile);
        printf("%u bytes written\n", len);
    } while (!feof(infile));

    free(buf);
    free(encbuf);
}
