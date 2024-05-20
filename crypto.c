#include "crypto.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>

static const u8 KEYGEN_CONST[0x10] = {
    0x1F, 0xF9, 0xE9, 0xAA, 
    0xC5, 0xFE, 0x04, 0x08, 
    0x02, 0x45, 0x91, 0xDC, 
    0x5D, 0x52, 0x76, 0x8A
};

// https://github.com/3DSGuy/Project_CTR/blob/master/ctrtool/deps/libnintendo-n3ds/src/CtrKeyGenerator.cpp#L24
s32 wrap_index(s32 i)
{
	return i < 0 ? ((i % 16) + 16) % 16 : (i > 15 ? i % 16 : i);
}

// https://github.com/3DSGuy/Project_CTR/blob/master/ctrtool/deps/libnintendo-n3ds/src/CtrKeyGenerator.cpp#L43
void n128_lrot(const u8 *in, u32 rot, u8 *out)
{
	u32 bit_shift;
    u32 byte_shift;

	rot = rot % 128;
	byte_shift = rot / 8;
	bit_shift = rot % 8;

	for (s32 i = 0; i < 16; i++) {
		out[i] = (in[wrap_index(i + byte_shift)] << bit_shift) | (in[wrap_index(i + byte_shift + 1)] >> (8 - bit_shift));
	}
}

// https://github.com/3DSGuy/Project_CTR/blob/master/ctrtool/deps/libnintendo-n3ds/src/CtrKeyGenerator.cpp#L29
void n128_rrot(const u8 *in, u32 rot, u8 *out)
{
	u32 bit_shift;
    u32 byte_shift;

	rot = rot % 128;
	byte_shift = rot / 8;
	bit_shift = rot % 8;

	for (s32 i = 0; i < 16; i++) {
		out[i] = (in[wrap_index(i - byte_shift)] >> bit_shift) | (in[wrap_index(i - byte_shift - 1)] << (8 - bit_shift));
	}
}

// https://github.com/3DSGuy/Project_CTR/blob/master/ctrtool/deps/libnintendo-n3ds/src/CtrKeyGenerator.cpp#L58
void n128_add(const u8 *a, const u8 *b, u8 *out)
{
	u8 carry = 0;
	u32 sum = 0;

	for (int i = 15; i >= 0; i--) {
		sum = a[i] + b[i] + carry;
		carry = sum >> 8;
		out[i] = sum & 0xff;
	}
}

// https://github.com/3DSGuy/Project_CTR/blob/master/ctrtool/deps/libnintendo-n3ds/src/CtrKeyGenerator.cpp#L94
void n128_xor(const u8 *a, const u8 *b, u8 *out)
{
	for (int i = 0; i < 16; i++) {
		out[i] = a[i] ^ b[i];
	}
}

// https://github.com/3DSGuy/Project_CTR/blob/master/ctrtool/deps/libnintendo-n3ds/src/CtrKeyGenerator.cpp#L3
void keyscrambler(u8 *keyX, u8 *keyY, u8 *out) {
    u8 x_rot[0x10];
    u8 key_xy[0x10];
    u8 key_xyc[0x10];

    n128_lrot(keyX, 2, x_rot);
    n128_xor(x_rot, keyY, key_xy);
    n128_add(key_xy, KEYGEN_CONST, key_xyc);
    n128_rrot(key_xyc, 41, out);
}

int hash_sha256(const u8 *in, u8 *out, u32 len) {
    EVP_MD_CTX *mdctx;
    
    if(!(mdctx = EVP_MD_CTX_new())) {
        EVP_MD_CTX_free(mdctx);
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        return -1;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        perror("Failed to init sha256\n");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    if (EVP_DigestUpdate(mdctx, in, len) != 1) {
        perror("Err Updating hash\n");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    u32 hash_len;
    if (EVP_DigestFinal_ex(mdctx, out, &hash_len) != 1) {
        perror("Err final hash\n");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    return hash_len;
}

int check_otp(u8 *otp) {
    u8 calculed_hash[0x20];
    
    u32 len = hash_sha256(otp, calculed_hash, 0xE0);

    for(int i = 0; i < 0x20; i++) {
        if(calculed_hash[i] != otp[0xE0+i]) {
            return 0;
        }
    }
    return 1;
}

int aes_cbc_128_decrypt(const u8 *in, u8 *out, aeskeys *keys, u32 blocklen) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int final_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        return 1;
    }

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, keys->normalkey, keys->IV)) {
        EVP_CIPHER_CTX_free(ctx);
        fprintf(stderr, "EVP_DecryptInit_ex failed\n");
        return 1;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if(1 != EVP_DecryptUpdate(ctx, out, (int*)&len, in, blocklen)) {
        EVP_CIPHER_CTX_free(ctx);
        fprintf(stderr, "EVP_DecryptUpdate failed\n");
        return 1;
    }
    final_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, out + len, (int*)&len)) {
        EVP_CIPHER_CTX_free(ctx);
        fprintf(stderr, "EVP_DecryptFinal_ex failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    final_len += len;

    EVP_CIPHER_CTX_free(ctx);
    EVP_cleanup();
    ERR_free_strings();
    return final_len;
}

int aes_cbc_128_encrypt(const u8 *in, u8 *out, aeskeys *keys, u32 blocklen) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int final_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        return 1;
    }

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, keys->normalkey, keys->IV)) {
        EVP_CIPHER_CTX_free(ctx);
        fprintf(stderr, "EVP_DecryptInit_ex failed\n");
        return 1;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if(1 != EVP_EncryptUpdate(ctx, out, (int*)&len, in, blocklen)) {
        EVP_CIPHER_CTX_free(ctx);
        fprintf(stderr, "EVP_DecryptUpdate failed\n");
        return 1;
    }
    final_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, out + len, (int*)&len)) {
        EVP_CIPHER_CTX_free(ctx);
        fprintf(stderr, "EVP_DecryptFinal_ex failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    final_len += len;

    EVP_CIPHER_CTX_free(ctx);
    EVP_cleanup();
    ERR_free_strings();
    return final_len;
}

void slot0x3FNormalAndIV(u8 boot9buff[0x10000], aeskeys *keys) {
    memcpy(keys, boot9buff + 0xb0e0/*keydata section*/ + 0x2600 /*RSA section*/, 0x20);
}

int aes_ctr_128_decrypt(const u8 *in, u8 *out, u8 *key, u8 *counter, u32 blocklen, bool is_final) {
    EVP_CIPHER_CTX *ctx;
    int len;

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        return 1;
    }

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, counter)) {
        EVP_CIPHER_CTX_free(ctx);
        fprintf(stderr, "EVP_DecryptInit_ex failed\n");
        return 1;
    }

    //EVP_CIPHER_CTX_set_padding(ctx, 0);

    if(!is_final) {
        if(1 != EVP_DecryptUpdate(ctx, out, (int*)&len, in, blocklen)) {
            EVP_CIPHER_CTX_free(ctx);
            fprintf(stderr, "EVP_DecryptUpdate failed\n");
            return 1;
        }
    } else {
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        if(1 != EVP_DecryptFinal_ex(ctx, out + len, (int*)&len)) {
            EVP_CIPHER_CTX_free(ctx);
            fprintf(stderr, "EVP_DecryptFinal_ex failed\n");
            ERR_print_errors_fp(stderr);
            return 1;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    EVP_cleanup();
    ERR_free_strings();
    return len;
}


void u32_to_u8_buff(u32 num, u8 *out) {
    memset(out, 0, 16);
    out[12] = (num >> 24) & 0xFF;
    out[13] = (num >> 16) & 0xFF;
    out[14] = (num >> 8) & 0xFF;
    out[15] = num & 0xFF;
}