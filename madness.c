#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

int rsa_encrypt(RSA*, FILE*, FILE*, const int);
int rsa_decrypt(RSA*, FILE*, FILE*, const int);

int main(int argc, char* argv[]) {
    RSA *private_key = NULL, *public_key = NULL;
    FILE *fp, *fpin, *fpout;
    char *input_filename = NULL, *key_filename = NULL, *output_filename = NULL;
    int decrypt = 0, verbose = 0;

    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            { "infile",  required_argument, NULL, 'i' },
            { "keyfile", required_argument, NULL, 'k' },
            { "decrypt", no_argument,       NULL, 'd' },
            { "verbose", no_argument,       NULL, 'v' },
            { "outfile", required_argument, NULL, 'o' },
            { NULL,      0,                 NULL,  0  }
        };

        int c;
        if ((c = getopt_long(argc, argv, "i:k:dvo:", long_options, &option_index)) == -1) break;

        switch (c) {
            case 0: break;
            case 'i': input_filename = optarg; break;
            case 'k': key_filename = optarg; break;
            case 'd': decrypt = 1; break;
            case 'v': verbose = 1; break;
            case 'o': output_filename = optarg; break;
            case '?': break;
            default: return 1;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "Unrecognized option %s, rest of the line ignored.\n", argv[optind]);
        return 1;
    }

    fp = fopen(key_filename, "r");
    if (!decrypt) {
        PEM_read_RSA_PUBKEY(fp, &public_key, NULL, NULL);
        if (verbose) printf("RSA %d\n", RSA_bits(public_key));
    } else {
        PEM_read_RSAPrivateKey(fp, &private_key, NULL, NULL);
        if (verbose) printf("RSA %d\n", RSA_bits(private_key));
    }
    fclose(fp);

    if (!input_filename || input_filename[0] == '-')
        fpin = stdin;
    else
        fpin = fopen(input_filename, "r");

    if (!output_filename || output_filename[0] == '-')
        fpout = stdout;
    else
        fpout = fopen(output_filename, "w");

    if (!decrypt)
        rsa_encrypt(public_key, fpin, fpout, verbose);
    else
        rsa_decrypt(private_key, fpin, fpout, verbose);

    if (fpin != stdin) fclose(fpin);
    if (fpout != stdout) fclose(fpout);

    return 0;
}

int rsa_encrypt(RSA* public_key, FILE* infile, FILE* outfile, const int verbose) {
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
        if (verbose) printf("%u bytes read for encryption\n", len);

        if ((len = RSA_public_encrypt(len, buf, encbuf, public_key, RSA_PKCS1_OAEP_PADDING)) != key_size) {
            ERR_print_errors_fp(stderr);
            free(buf);
            free(encbuf);
            return -1;
        }
        if (verbose) printf("%u bytes encrypted\n", len);

        // Write it to outfile
        len = fwrite(encbuf, 1, len, outfile);
        if (verbose) printf("%u bytes written\n", len);

    } while (!feof(infile));

    free(buf);
    free(encbuf);

    return 0;
}

int rsa_decrypt(RSA* private_key, FILE* infile, FILE* outfile, const int verbose) {
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
        if (verbose) printf("%u bytes read for decryption\n", len);

        if ((len = RSA_private_decrypt(len, buf, decbuf, private_key, RSA_PKCS1_OAEP_PADDING)) == -1) {
            ERR_print_errors_fp(stderr);
            free(buf);
            free(decbuf);
            return -1;
        }
        if (verbose) printf("%u bytes decrypted\n", len);

        // Write it to outfile
        len = fwrite(decbuf, 1, len, outfile);
        if (verbose) printf("%u bytes written\n", len);

    } while (!feof(infile));

    free(buf);
    free(decbuf);

    return 0;
}
