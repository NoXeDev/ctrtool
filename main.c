#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>

#include "nand.h"

#include "fatfs/ff.h"
void disk_deinitialize(void);

typedef struct {
    const char *name;
    const char *description;
    void (*func)(int argc, char *argv[]);
} Command;

void command_help(int argc, char *argv[]);
void extractpart(int argc, char *argv[]);
void list_dir(int argc, char *argv[]);

Command commands[] = {
    {"help", "Show help pannel", command_help},
    {"extractpart", "Decrypt and extract a nand partition ", extractpart},
    {"listdir", "List all files and dirs into CTRNAND partition", list_dir},
    {NULL, NULL, NULL}
};

Partitions partitions[] = {
    {1, "firm0", "Firmware partition.", 0x0B130000, 0x00400000, KEY0x06},
    {2, "firm1", "Firmware partition. (Backup partition, same as above)", 0x0B530000, 0x00400000, KEY0x06},
    {3, "nand", "CTR-NAND FAT16 File System. (OLD 3DS)", 0x0B95CA00, 0x2F3E3600, KEY0x04},
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

    if(0 != initNandCrypto(ctrnand)) {
        printf("Failed to init nand crypto\n");
        return;
    }

    FILE *out = fopen(out_path, "wb");
    decrypt_and_extract_nand_partition(ctrnand, selectedPartition->offset, selectedPartition->size, selectedPartition->keyslotId, out);
    fclose(out);

    printf("Partition %s extracted to %s\n", selectedPartition->name, out_path);
    // Close nand file
    fclose(ctrnand);
}

void list_dir(int argc, char *argv[]) {
    FATFS fs;
    int res = f_mount(&fs, "oldctrnand:", 1);
    if(res != FR_OK) {
        printf("Failed to mount filesystem\n");
        return;
    }

    FILINFO fno;
    DIR dir;
    res = f_opendir(&dir, "/");
    if(res != FR_OK) {
        printf("Failed to open directory\n");
        return;
    }

    while (1) {
        res = f_readdir(&dir, &fno); 
        if (res != FR_OK || fno.fname[0] == 0) {
            break;  // Break on error or end of directory
        }
        if (fno.fattrib & AM_DIR) {
            printf("[DIR]  %s\n", fno.fname);  // It's a directory
        } else {
            printf("[FILE] %s\n", fno.fname);  // It's a file
        }
    }
    f_closedir(&dir);
    disk_deinitialize();
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