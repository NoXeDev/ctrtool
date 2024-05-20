#pragma once
#include "utils.h"
#include <stdbool.h>

typedef struct aeskeys {
    u8 normalkey[0x10];
    u8 IV[0x10];
} aeskeys;

void slot0x3FNormalAndIV(u8 boot9buff[0x10000], aeskeys *keys);
void u32_to_u8_buff(u32 num, u8 *out);

int aes_cbc_128_decrypt(const u8 *in, u8 *out, aeskeys *keys, u32 blocklen);
int aes_cbc_128_encrypt(const u8 *in, u8 *out, aeskeys *keys, u32 blocklen);
int aes_ctr_128_decrypt(const u8 *in, u8 *out, u8 *key, u8 *counter, u32 blocklen, bool is_final);
int hash_sha256(const u8 *in, u8 *out, u32 len);
void n128_add(const u8 *a, const u8 *b, u8 *out);

int check_otp(u8 *otp);

void keyscrambler(u8 *keyX, u8 *keyY, u8 *out);