#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define BUFFER_SIZE 512

int main(void) {
    RSA* private_key = NULL;
    RSA* public_key = NULL;
    FILE* fp;
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

    // Read message to be encrypted
    fp = fopen("message.txt", "r");
    len = fread(buf, 1, 1024, fp);
    fclose(fp);
    //printf("%s\n", buf);
    printf("%u bytes read from `message.txt'\n", len);

    // Check if message length is OK
    // Quoting from man page:
    // "flen must not be more than RSA_size(rsa) - 42 for RSA_PKCS1_OAEP_PADDING"
    if (len > RSA_size(public_key) - 42) {
        fprintf(stderr, "Message length too long!\nMust not be greater than %u\n", RSA_size(public_key) - 42);
        return 1;
    }

    // RSA ENCRYPTION ////////////////////////////////////////////////////////////////////////////////////////////////
    char* encrypted_message = malloc(RSA_size(public_key));
    if (RSA_public_encrypt(len, buf, encrypted_message, public_key, RSA_PKCS1_OAEP_PADDING) != RSA_size(public_key)) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Write it out to a file
    fp = fopen("encrypted_message.txt", "w");
    len = fwrite(encrypted_message, 1, RSA_size(public_key), fp);
    free(encrypted_message);
    fclose(fp);
    printf("%u bytes written to `encrypted_message.txt'\n", len);
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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
