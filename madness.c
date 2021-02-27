#include <stdio.h>
#include <openssl/pem.h>

int main(void) {
    RSA* private_key = NULL;
    RSA* public_key = NULL;

    FILE* private_key_pem = fopen("key.pem", "r");
    PEM_read_RSAPrivateKey(private_key_pem, &private_key, NULL, NULL);
    fclose(private_key_pem);

    FILE* public_key_pem = fopen("pubkey.pem", "r");
    PEM_read_RSA_PUBKEY(public_key_pem, &public_key, NULL, NULL);
    fclose(public_key_pem);

    printf("Private key size = %d\n", RSA_bits(private_key));
    printf("Public key size = %d\n", RSA_bits(public_key));

    return 0;
}
