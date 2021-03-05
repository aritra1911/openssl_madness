#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

int rsa_encrypt(RSA*, FILE*, FILE*, const int);
int rsa_decrypt(RSA*, FILE*, FILE*, const int);
void print_usage(const char*);

void print_usage(const char* bin) {
    printf("Usage : %s [-i FILE] -k PEM_FILE -(e|d) [-o FILE] [-v]\n"
           "RSA Encryption / Decryption Tool using OpenSSL API\n\n"

           "    -h, --help        Show this help and exit\n\n"

           "    -i, --infile      Specify file to be read for data. When omitted, stdin will be used by default.\n\n"

           "    -k, --keyfile     Specify public / private key file in PEM format. If --decrypt flag is specified, the\n"
           "                      specified key is treated as a private key, otherwise the same is treated as a public\n"
           "                      key when --encrypt is specified.\n\n"

           "    -o, --outfile     Specify file to write data to. When omitted, stdout will be used by default.\n\n"

           "    -e, --encrypt     Specify encryption operation to be performed on the read data with value of --keyfile\n"
           "                      treated as the public key.\n\n"

           "    -d, --decrypt     Signify decryption operation to be performed on the read data with value of --keyfile\n"
           "                      treated as the private key.\n\n"

           "    -v, --verbose     Show RSA size, blocks of data read, encrypted / decrypted, written.\n", bin);
}

int main(int argc, char* argv[]) {
    RSA *private_key = NULL, *public_key = NULL;
    FILE *fp, *fpin, *fpout;
    char *input_filename = NULL, *key_filename = NULL, *output_filename = NULL;
    int decrypt = -1, verbose = 0;

    if (argc < 2) {
        fprintf(stderr, "No arguments supplied\n");
        putchar('\n');
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            { "infile",  required_argument, NULL, 'i' },
            { "keyfile", required_argument, NULL, 'k' },
            { "encrypt", no_argument,       NULL, 'e' },
            { "decrypt", no_argument,       NULL, 'd' },
            { "verbose", no_argument,       NULL, 'v' },
            { "outfile", required_argument, NULL, 'o' },
            { "help",    no_argument,       NULL, 'h' },
            { NULL,      0,                 NULL,  0  }
        };

        int c;
        if ((c = getopt_long(argc, argv, "i:k:edvo:h", long_options, &option_index)) == -1) break;

        switch (c) {
            case 0: break;
            case 'i': input_filename = optarg; break;
            case 'k': key_filename = optarg; break;

            case 'e':
                if (decrypt == 1) {
                    // Only way to end up here is iff `--decrypt' && `--encrypt' are specified together
                    fprintf(stderr, "How the hell do you decrypt & encrypt at the same time?\n"
                                    "Specify either `--decrypt' or `--encrypt', not both\n");
                    putchar('\n');
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                decrypt = 0; break;

            case 'd':
                if (decrypt == 0) {
                    // Only way to end up here is iff `--encrypt' && `--decrypt' are specified together
                    fprintf(stderr, "How the hell do you encrypt & decrypt at the same time?\n"
                                    "Specify either `--encrypt' or `--decrypt', not both\n");
                    putchar('\n');
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                decrypt = 1; break;

            case 'v': verbose = 1; break;
            case 'o': output_filename = optarg; break;

            case 'h':
                print_usage(argv[0]);
                return EXIT_SUCCESS;

            case '?': break;
            default: return 1;
        }
    }

    // If any other argument supplied, report an error since it's not clear what the user is trying to do
    if (optind < argc) {
        fprintf(stderr, "Unrecognized option %s\n", argv[optind]);
        putchar('\n');
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // --keyfile is not optional
    if (!key_filename) {
        fprintf(stderr, "What key to use?\nSpecify a PEM formatted file using `--keyfile'\n");
        putchar('\n');
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // Either `--encrypt' or `--decrypt' MUST be specified
    if (decrypt == -1) {
        fprintf(stderr, "Tell me what to do?\nSpecify whether to `--encrypt' or `--decrypt'\n");
        putchar('\n');
        print_usage(argv[0]);
        return EXIT_FAILURE;
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

    return EXIT_SUCCESS;
}

int rsa_encrypt(RSA* public_key, FILE* infile, FILE* outfile, const int verbose) {
    int len, key_size = RSA_size(public_key);
    char *buf, *encbuf;
    size_t flen;

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
        if (!(flen = fread(buf, 1, key_size - 42, infile))) break;
        if (verbose) printf("%lu bytes read for encryption\n", flen);

        if ((len = RSA_public_encrypt(flen, (unsigned char*) buf, (unsigned char*) encbuf,
                                      public_key, RSA_PKCS1_OAEP_PADDING)) != key_size) {
            ERR_print_errors_fp(stderr);
            free(buf);
            free(encbuf);
            return -1;
        }
        if (verbose) printf("%d bytes encrypted\n", len);

        // Write it to outfile
        flen = fwrite(encbuf, 1, len, outfile);
        if (verbose) printf("%lu bytes written\n", flen);

    } while (!feof(infile));

    free(buf);
    free(encbuf);

    return 0;
}

int rsa_decrypt(RSA* private_key, FILE* infile, FILE* outfile, const int verbose) {
    int len, key_size = RSA_size(private_key);
    char *buf, *decbuf;
    size_t flen;

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
        if (!(flen = fread(buf, 1, key_size, infile))) break;
        if (verbose) printf("%lu bytes read for decryption\n", flen);

        if ((len = RSA_private_decrypt(flen, (unsigned char*) buf, (unsigned char*) decbuf,
                                       private_key, RSA_PKCS1_OAEP_PADDING)) == -1) {
            ERR_print_errors_fp(stderr);
            free(buf);
            free(decbuf);
            return -1;
        }
        if (verbose) printf("%d bytes decrypted\n", len);

        // Write it to outfile
        flen = fwrite(decbuf, 1, len, outfile);
        if (verbose) printf("%lu bytes written\n", flen);

    } while (!feof(infile));

    free(buf);
    free(decbuf);

    return 0;
}
