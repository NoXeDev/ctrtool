#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>

#include "nand.h"

typedef struct {
    const char *name;
    const char *description;
    void (*func)(int argc, char *argv[]);
} Command;

void command_help(int argc, char *argv[]);
void extractpart(int argc, char *argv[]);

Command commands[] = {
    {"help", "Show help pannel", command_help},
    {"extractpart", "Decrypt and extract a nand partition ", extractpart},
    {NULL, NULL, NULL}
};

Partitions partitions[] = {
    {1, "firm0", "Firmware partition.", 0x0B130000, 0x00400000, 0x6},
    {2, "firm1", "Firmware partition. (Backup partition, same as above)", 0x0B530000, 0x00400000, 0x6},
    {3, "nand", "CTR-NAND FAT16 File System. (OLD 3DS)", 0x0B95CA00, 0x2F3E3600, 0x4},
    {0, NULL, NULL, 0, 0, 0}
};

void execute_command(const char *name, int argc, char *argv[]) {
    for (int i = 0; commands[i].name != NULL; i++) {
        if (strcmp(commands[i].name, name) == 0) {
            commands[i].func(argc, argv);
            return;
        }
    }
    fprintf(stderr, "Unknown command: %s\n", name);
    command_help(0, NULL);
}

void command_help(int argc, char *argv[]) {
    printf("Commands list:\n");
    for (int i = 0; commands[i].name != NULL; i++) {
        printf("  %s: %s\n", commands[i].name, commands[i].description);
    }
}

void extractpart(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <partition number> <out path filename>\n", basename(argv[0]));
        printf("Partitions list:\n");
        for (int i = 0; partitions[i].name != NULL; i++) {
            printf("  (%d) %s: %s\n", partitions[i].ID, partitions[i].name, partitions[i].description);
        }
        printf("\n");
        return;
    }

    int partition_id = atoi(argv[1]);
    if (partition_id < 1 || partition_id > 3) {
        fprintf(stderr, "Invalid partition number: %s\n", argv[1]);
        return;
    }

    Partitions *selectedPartition;
    for (int i = 0; partitions[i].name != NULL; i++) {
        if (partitions[i].ID == partition_id) {
            selectedPartition = &partitions[i];
            break;
        }
    }

    const char *out_path = argv[2];

    // Open nand file and bootrom file
    FILE* ctrnand = fopen("ctrnand.bin", "rb");
    FILE* boot9 = fopen("boot9.bin", "rb");

    // Create essential buffer
    EssentialBackup essentialsDatas;

    // Create buffer and read bootrom9 datas
    u8 boot9buff[0x10000];
    size_t bytes_read = fread(boot9buff, 1, 0x10000, boot9);
    fclose(boot9);

    // Read essentials nand datas
    if(extractEssentials(ctrnand, &essentialsDatas) != 0) {
        printf("Error parsing nand\n");
        return;
    }

    Otp otp;
    if(decrypt_verify_otp(essentialsDatas.otp, boot9buff, &otp) != 0) {
        printf("Error decrypting otp\n");
        return;
    }
    
    keyslots ctrnandkeys;
    setupKeyslots(&otp, boot9buff, &ctrnandkeys);

    u8 *selectedKeyslot;
    switch (selectedPartition->keyslotId) {
        case 4:
            selectedKeyslot = ctrnandkeys.key0x04;
            break;
        case 5:
            selectedKeyslot = ctrnandkeys.key0x05;
            break;
        case 6:
            selectedKeyslot = ctrnandkeys.key0x06;
            break;
        case 7:
            selectedKeyslot = ctrnandkeys.key0x07;
            break;
        default:
            fprintf(stderr, "Invalid keyslot ID: %d\n", selectedPartition->keyslotId);
            return;
    }

    u8 cryptoCid[0x10];
    getNandCryptoCid(essentialsDatas.nand_cid, cryptoCid);

    FILE *out = fopen(out_path, "wb");
    decrypt_and_extract_nand_partition(ctrnand, selectedPartition->offset, selectedPartition->size, selectedKeyslot, cryptoCid, out);
    fclose(out);

    printf("Partition %s extracted to %s\n", selectedPartition->name, out_path);
    // Close nand file
    fclose(ctrnand);
}

int main(int argc, char *argv[]) {
     if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [arguments]\n", basename(argv[0]));
        command_help(0, NULL);
        return EXIT_FAILURE;
    }

    const char *command_name = argv[1];
    execute_command(command_name, argc - 1, &argv[1]);

    return EXIT_SUCCESS;
}