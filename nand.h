#pragma once
#include "utils.h"
#include "exefs.h"
#include <stdio.h>

// size of /ro/sys/HWCAL0.dat and /ro/sys/HWCAL1.dat
#define SIZE_HWCAL 0x9D0
#define BLOCK_SIZE 4096

// KEYSLOTS IDs DEFINITION
#define KEY0x04 4
#define KEY0x05 5
#define KEY0x06 6
#define KEY0x07 7

typedef struct
{
    u8 sig[0x100]; //RSA-2048 signature of the NCCH header, using SHA-256
    char magic[4]; //NCCH
    u32 contentSize; //Media unit
    u8 partitionId[8];
    u8 makerCode[2];
    u16 version;
    u8 reserved1[4];
    u8 programID[8];
    u8 reserved2[0x10];
    u8 logoHash[0x20]; //Logo Region SHA-256 hash
    char productCode[0x10];
    u8 exHeaderHash[0x20]; //Extended header SHA-256 hash
    u32 exHeaderSize; //Extended header size
    u32 reserved3;
    u8 flags[8];
    u32 plainOffset; //Media unit
    u32 plainSize; //Media unit
    u32 logoOffset; //Media unit
    u32 logoSize; //Media unit
    u32 exeFsOffset; //Media unit
    u32 exeFsSize; //Media unit
    u32 exeFsHashSize; //Media unit
    u32 reserved4;
    u32 romFsOffset; //Media unit
    u32 romFsSize; //Media unit
    u32 romFsHashSize; //Media unit
    u32 reserved5;
    u8 exeFsHash[0x20]; //ExeFS superblock SHA-256 hash
    u8 romFsHash[0x20]; //RomFS superblock SHA-256 hash
} Ncch;

// /rw/sys/LocalFriendCodeSeed_B (/_A) file
// see: http://3dbrew.org/wiki/Nandrw/sys/LocalFriendCodeSeed_B
typedef struct {
    u8 signature[0x100];
    u8 unknown[0x8]; // normally zero
    u8 codeseed[0x8]; // the actual data
} __attribute__((packed, aligned(4))) LocalFriendCodeSeed;

// /private/movable.sed file
// see: http://3dbrew.org/wiki/Nand/private/movable.sed
typedef struct {
    u8 magic[0x4]; // "SEED"
    u8 indicator[0x4]; // uninitialized all zero, otherwise u8[1] nonzero
    LocalFriendCodeSeed codeseed_data;
    u8 keyy_high[8];
    u8 unknown[0x10];
    u8 cmac[0x10];
} __attribute__((packed, aligned(4))) MovableSed;

// /rw/sys/SecureInfo_A (/_B) file
// see: http://3dbrew.org/wiki/Nandrw/sys/SecureInfo_A
typedef struct {
    u8 signature[0x100];
    u8 region;
    u8 unknown;
    char serial[0xF];
} __attribute__((packed, aligned(1))) SecureInfo;

typedef struct {
    ExeFsHeader header;
    u8 nand_hdr[0x200];
    SecureInfo secinfo;
    u8 padding_secinfo[0x200 - (sizeof(SecureInfo)%0x200)];
    MovableSed movable;
    u8 padding_movable[0x200 - (sizeof(MovableSed)%0x200)];
    LocalFriendCodeSeed frndseed;
    u8 padding_frndseed[0x200 - (sizeof(LocalFriendCodeSeed)%0x200)];
    u8 nand_cid[0x10];
    u8 padding_nand_cid[0x200 - 0x10];
    u8 otp[0x100];
    u8 padding_otp[0x200 - 0x100];
    u8 hwcal0[SIZE_HWCAL];
    u8 padding_hwcal0[0x200 - (SIZE_HWCAL%0x200)];
    u8 hwcal1[SIZE_HWCAL];
    u8 padding_hwcal1[0x200 - (SIZE_HWCAL%0x200)];
} __attribute__((packed, aligned(16))) EssentialBackup;

typedef struct {
    u32 magic;
    u32 deviceId;
    u8 fallbackKeyY[16];
    u8 ctcertFlags;
    u8 ctcertIssuer;
    u8 timestampYear;
    u8 timestampMonth;
    u8 timestampDay;
    u8 timestampHour;
    u8 timestampMinute;
    u8 timestampSecond;
    u32 ctcertExponent;
    u8 ctcertPrivK[32];
    u8 ctcertSignature[60];
    u8 zero[16];
    u8 random[0x50];
    u8 hash[256 / 8];
} __attribute__((__packed__)) Otp;

typedef struct keyslots {
    u8 key0x04[0x10];
    u8 key0x05[0x10];
    u8 key0x06[0x10];
    u8 key0x07[0x10];
} Keyslots;

typedef struct {
    const u8 ID;
    const char *name;
    const char *description;
    const u32 offset;
    const u32 size;
    const u8 keyslotId;
} Partitions;

int initNandCrypto(FILE *ctrnand);
int readNandBlock(FILE *ctrnand, long offset, size_t size, char* buffer);
int extractEssentials(FILE *ctrnand, EssentialBackup *out);
int decrypt_verify_otp(u8 *in, u8 *boot9buff, Otp *out);
int setupKeyslots(const Otp *otp, u8 *boot9buff, Keyslots *out);
int getNandCryptoCid(const u8 *cid, u8 *out);
int decrypt_nand_partition(FILE *ctrnand, u32 offset, u32 size, u32 keyslotId, u8 *out);
int decrypt_and_extract_nand_partition(FILE *ctrnand, u32 offset, u32 size, u32 keyslotId, FILE *outfile);