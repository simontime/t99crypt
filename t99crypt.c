#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"

#define FNV_SEED  0x811C9DC5
#define FNV_PRIME 0x1000193

typedef struct
{
    uint32_t version;
    uint32_t hash;
    uint8_t  key[16];
} save_header_t;

/* Constant IV/nonce for AES-CTR crypto operations */
const uint8_t aes_iv[] =
{ 0xFA, 0x3C, 0xFF, 0x61, 0x34, 0xBE, 0xFD, 0x09, 0x00, 0x7D, 0x12, 0xCE, 0x0A, 0x82, 0xDF, 0x10 };

uint32_t calculate_fnv1a(const void *data, size_t len)
{
    uint8_t *ptr  = (uint8_t *)data;
    uint32_t hash = FNV_SEED;
    
    while (len--)
        hash = (hash ^ *ptr++) * FNV_PRIME;
    
    return hash;
}

int main(int argc, char **argv)
{
    struct AES_ctx aes;
    bool decrypt;
    FILE *save;
    uint8_t *buf;
    uint32_t orig_hash, calc_hash;
    save_header_t *hdr;
    size_t len;
    
    if (argc != 3)
        goto _print_usage;
    
    if      (strcmp(argv[1], "decrypt") == 0) decrypt = true;
    else if (strcmp(argv[1], "encrypt") == 0) decrypt = false;
    else goto _print_usage;
    
    if ((save = fopen(argv[2], "rb+")) == NULL)
    {
        perror("Error opening save file");
        return 1;
    }
    
    /* Get file length */
    fseek(save, 0, SEEK_END);
    len = ftell(save);
    rewind(save);
    
    /* Allocate and read data */
    buf = malloc(len);
    fread(buf, 1, len, save);
    rewind(save);
    
    hdr = (save_header_t *)buf;
    
    /* Store and nullify hash */
    orig_hash = hdr->hash;        
    hdr->hash = 0;
    
    AES_init_ctx_iv(&aes, hdr->key, aes_iv);
    
    if (decrypt)
    {
        /* Calculate hash */
        calc_hash = calculate_fnv1a(buf, len);
        
        /* Verify match with stored hash */
        if (orig_hash != calc_hash)
        {
            fprintf(stderr, "Error decrypting save file: Invalid hash (calculated = 0x%08x, stored = 0x%08x)\n", calc_hash, orig_hash);
            return 1;
        }
        
        AES_CTR_xcrypt_buffer(&aes, buf + sizeof(save_header_t), len - sizeof(save_header_t));
        
        fwrite(buf, 1, len, save);
    }
    else
    {
        AES_CTR_xcrypt_buffer(&aes, buf + sizeof(save_header_t), len - sizeof(save_header_t));
        
        hdr->hash = calculate_fnv1a(buf, len);
        
        fwrite(buf, 1, len, save);
    }
    
    fclose(save);
    free(buf);
    
    printf("Done!");
    
    return 0;
    
_print_usage:
    printf("Usage:\n"
           "%s decrypt save.bin - verify and decrypt save file\n"
           "%s encrypt save.bin - encrypt and hash save file\n",
           *argv, *argv);
    
    return 0;
}