#include "nand.h"
#include <string.h>
#include <stdlib.h>

#include "crypto.h"

static Otp s_otp;
static Keyslots s_ctrnandkeys;
static EssentialBackup s_essentialsDatas;
static u8 s_cryptoCid[0x10];

u8 *getKeyslot(u32 keyslotId) {
    switch (keyslotId) {
        case KEY0x04:
            return s_ctrnandkeys.key0x04;
        case KEY0x05:
            return s_ctrnandkeys.key0x05;
        case KEY0x06:
            return s_ctrnandkeys.key0x06;
        case KEY0x07:
            return s_ctrnandkeys.key0x07;
        default:
            fprintf(stderr, "Invalid keyslot ID: %d\n", keyslotId);
            return NULL;
    }
}

int initNandCrypto(FILE *ctrnand) {
    // Read boot9
    FILE* boot9 = fopen("boot9.bin", "rb");
    u8 boot9buff[0x10000];
    size_t bytes_read = fread(boot9buff, 1, 0x10000, boot9);
    fclose(boot9);
    
    if(extractEssentials(ctrnand, &s_essentialsDatas) != 0) {
        return 1; // Error parsing NAND
    }

    if(decrypt_verify_otp(s_essentialsDatas.otp, boot9buff, &s_otp) != 0) {
        return 2; // Error decrypt & parsing OTP
    }
    
    setupKeyslots(&s_otp, boot9buff, &s_ctrnandkeys);
    getNandCryptoCid(s_essentialsDatas.nand_cid, s_cryptoCid);
    return 0; // OK
}

int readNandBlock(FILE *ctrnand, long offset, size_t size, char* buffer) {
    if (fseek(ctrnand, offset, SEEK_SET) != 0) {
        perror("Err fseek()");
        fclose(ctrnand);
        return 2;
    }

    size_t bytes_read = fread(buffer, 1, size, ctrnand);
    if (bytes_read != size) {
        if (feof(ctrnand)) {
            printf("File out of bound.\n");
            fclose(ctrnand);
            return 3;
        } else if (ferror(ctrnand)) {
            perror("Err read");
            fclose(ctrnand);
            return 4;
        }
    }
    return 0;
}


int extractEssentials(FILE *ctrnand, EssentialBackup *out) {
    if(readNandBlock(ctrnand, 0x200, sizeof(EssentialBackup), (char*)out) != 0) {
        printf("Error parsing nand\n");
        return 1;
    }

    if(ValidateExeFsHeader(&out->header, sizeof(EssentialBackup)) != 0) {
        printf("Essentials backup invalid !\n");
        return 1;
    }

    return 0;
}

int decrypt_verify_otp(u8 *in, u8 *boot9buff, Otp *out) {
    aeskeys otpkeys;
    slot0x3FNormalAndIV(boot9buff, &otpkeys);

    int len = aes_cbc_128_decrypt(in, (u8 *)out, &otpkeys, 0x100);
    if(len == 0) {
        printf("Error decrypting otp\n");
        return 1;
    }

    if(!check_otp((u8 *)out)) {
        printf("OTP invalid !\n");
        return 1;
    }
    return 0;
}

int setupKeyslots(const Otp *otp, u8 *boot9buff, Keyslots *out) {
    u8 tmp[0x40];
    memcpy(&tmp, &otp->random, 0x1C);
    memcpy(&tmp[0x1C], &boot9buff[0xd860], 0x24);

    u8 tmphash[0x20];
    hash_sha256(tmp, tmphash, sizeof(tmp));

    u8 keyX3F[0x10];
    u8 keyY3F[0X10]; 
    memcpy(&keyX3F, &tmphash, 0x10);
    memcpy(&keyY3F, &tmphash[0x10], 0x10);

    u8 normalKey3F[0x10];
    u8 IVCodeBlockX[0x10];

    u8 codeBlockX[0x10];
    keyscrambler(keyX3F, keyY3F, normalKey3F);
    memcpy(&codeBlockX, &boot9buff[0xd860+0x40-0x1C], 0x10);
    memcpy(&IVCodeBlockX, &boot9buff[0xd860+0x40-0x1C+0x10], 0x10);

    aeskeys Key3FCodeBlockX;
    memcpy(&Key3FCodeBlockX.normalkey, &normalKey3F, 0x10);
    memcpy(&Key3FCodeBlockX.IV, &IVCodeBlockX, 0x10);

    u8 KeyX0x04_0x07[0x10];
    int len = aes_cbc_128_encrypt(codeBlockX, KeyX0x04_0x07, &Key3FCodeBlockX, 0x10);
    if(len == 0) {
        printf("Error encrypting codeBlockX\n");
        return 1;
    }

    keyscrambler(KeyX0x04_0x07, &boot9buff[0xDA50], out->key0x04);
    keyscrambler(KeyX0x04_0x07, &boot9buff[0xDA50+0x10], out->key0x05);
    keyscrambler(KeyX0x04_0x07, &boot9buff[0xDA50+0x20], out->key0x06);
    keyscrambler(KeyX0x04_0x07, &boot9buff[0xDA50+0x30], out->key0x07);
    
    return 0;
}

int getNandCryptoCid(const u8 *cid, u8 *out) {
    u8 hashedCid[0x20];

    int len = hash_sha256(cid, hashedCid, 0x10);
    if(len == -1) {
        printf("Error hashing cid\n");
        return 1;
    }

    memcpy(out, hashedCid, 0x10);
    return 0;
}

int decrypt_nand_partition(FILE *ctrnand, u32 offset, u32 size, u32 keyslotId, u8 *out) {
    u32 block_count = size / BLOCK_SIZE;
    u8 rawblock[BLOCK_SIZE];

    u8 counter[0x10];
    u8 shiftedOffset[0x10];
    u32_to_u8_buff(offset >> 4, shiftedOffset);
    n128_add(s_cryptoCid, shiftedOffset, counter);

    u32 outoffset = 0;
    do {
        int res = readNandBlock(ctrnand, offset, BLOCK_SIZE, (char *)rawblock);
        if(res != 0) {
            printf("Error reading nand partition\n");
            return 1;
        }
        u8 *keyslot = getKeyslot(keyslotId);
        u32 len = aes_ctr_128_decrypt(rawblock, out + outoffset, keyslot, counter, BLOCK_SIZE, block_count == 0);
        if(len == 1) {
            printf("Error decrypting nand partition\n");
            return 1;
        }

        offset += BLOCK_SIZE;
        outoffset += BLOCK_SIZE;

        u32_to_u8_buff(offset >> 4, shiftedOffset);
        n128_add(s_cryptoCid, shiftedOffset, counter);
    }
    while(block_count--);
    return 0;
}

int decrypt_and_extract_nand_partition(FILE *ctrnand, u32 offset, u32 size, u32 keyslotId, FILE *outfile) {
    u32 block_count = size / BLOCK_SIZE;
    s32 final_block = size % BLOCK_SIZE;

    u8 rawblock[BLOCK_SIZE];
    u8 decryptedblock[BLOCK_SIZE];

    u8 counter[0x10];
    u8 shiftedOffset[0x10];
    u32_to_u8_buff(offset >> 4, shiftedOffset);
    n128_add(s_cryptoCid, shiftedOffset, counter);

    do {
        int res = readNandBlock(ctrnand, offset, block_count == 0 ? final_block : BLOCK_SIZE, (char *)rawblock);
        if(res != 0) {
            printf("Error reading nand partition\n");
            return 1;
        }
        u8 *keyslot = getKeyslot(keyslotId);
        u32 len = aes_ctr_128_decrypt(rawblock, decryptedblock, keyslot, counter, block_count == 0 ? final_block : BLOCK_SIZE, (block_count == 0) && (final_block == 0));
        if(len == 1) {
            printf("Error decrypting nand partition\n");
            return 1;
        }

        fwrite(decryptedblock, 1, len, outfile);
        offset += BLOCK_SIZE;

        u32_to_u8_buff(offset >> 4, shiftedOffset);
        n128_add(s_cryptoCid, shiftedOffset, counter);

        if(block_count == 0) {
            final_block = -1;
        }
    }
    while(block_count-- && final_block > -1);

    return 0;
}