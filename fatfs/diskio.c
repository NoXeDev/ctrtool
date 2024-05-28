/*-----------------------------------------------------------------------*/
/* Low level disk I/O module SKELETON for FatFs     (C)ChaN, 2019        */
/*-----------------------------------------------------------------------*/
/* If a working storage control module is available, it should be        */
/* attached to the FatFs via a glue function rather than modifying it.   */
/* This is an example of glue functions to attach various exsisting      */
/* storage control modules to the FatFs module with a defined API.       */
/*-----------------------------------------------------------------------*/

#include "ff.h"			/* Obtains integer types */
#include "diskio.h"		/* Declarations of disk functions */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "../nand.h"

#define OLDCTRNAND_OFFSET 0x0B95CA00
#define NEWCTRNAND_OFFSET 0x0B95AE00

static FILE *nandFile = NULL;
static char *nandFileName = "ctrnand.bin";

/*-----------------------------------------------------------------------*/
/* Get Drive Status                                                      */
/*-----------------------------------------------------------------------*/

DSTATUS disk_status (
	BYTE pdrv		/* Physical drive nmuber to identify the drive */
)
{
	if (nandFile == NULL || !isNandInit()) {
        return STA_NOINIT;
    }
    return RES_OK;
}

/*-----------------------------------------------------------------------*/
/* Inidialize a Drive                                                    */
/*-----------------------------------------------------------------------*/

DSTATUS disk_initialize (
	BYTE pdrv				/* Physical drive nmuber to identify the drive */
)
{
	if (nandFile != NULL && isNandInit()) {
        return RES_OK; // nand file already open
    }
    
    nandFile = fopen(nandFileName, "r+b");
    if (nandFile == NULL) {
        return STA_NOINIT;
    }

	int res = initNandCrypto(nandFile);
	if(res != 0) {
		fclose(nandFile);
		return STA_NOINIT;
	}

    return RES_OK;
}



/*-----------------------------------------------------------------------*/
/* Read Sector(s)                                                        */
/*-----------------------------------------------------------------------*/

DRESULT disk_read (
	BYTE pdrv,		/* Physical drive nmuber to identify the drive */
	BYTE *buff,		/* Data buffer to store read data */
	LBA_t sector,	/* Start sector in LBA */
	UINT count		/* Number of sectors to read */
)
{
	if (nandFile == NULL && !isNandInit()) {
        return RES_NOTRDY;
    }
    
    int res = readFsNandBlock(
		nandFile, 
		(isNew3DS(nandFile) == 0 ? OLDCTRNAND_OFFSET : NEWCTRNAND_OFFSET) + (sector * 512), 
		count, 
		(isNew3DS(nandFile) == 0 ? KEY0x04 : KEY0x05),
		buff
	);

    if (res != count) {
        return RES_ERROR;
    }
    
    return RES_OK;
}



/*-----------------------------------------------------------------------*/
/* Write Sector(s)                                                       */
/*-----------------------------------------------------------------------*/

#if FF_FS_READONLY == 0

DRESULT disk_write (
	BYTE pdrv,			/* Physical drive nmuber to identify the drive */
	const BYTE *buff,	/* Data to be written */
	LBA_t sector,		/* Start sector in LBA */
	UINT count			/* Number of sectors to write */
)
{
	DRESULT res;
	int result;

	switch (pdrv) {
	case DEV_RAM :
		// translate the arguments here

		result = RAM_disk_write(buff, sector, count);

		// translate the reslut code here

		return res;

	case DEV_MMC :
		// translate the arguments here

		result = MMC_disk_write(buff, sector, count);

		// translate the reslut code here

		return res;

	case DEV_USB :
		// translate the arguments here

		result = USB_disk_write(buff, sector, count);

		// translate the reslut code here

		return res;
	}

	return RES_PARERR;
}

#endif


/*-----------------------------------------------------------------------*/
/* Miscellaneous Functions                                               */
/*-----------------------------------------------------------------------*/

DRESULT disk_ioctl (
	BYTE pdrv,		/* Physical drive nmuber (0..) */
	BYTE cmd,		/* Control code */
	void *buff		/* Buffer to send/receive control data */
)
{
	switch (cmd) {
        default:
            return RES_PARERR;
    }
}


void disk_deinitialize(void) {
    if (nandFile != NULL) {
        fclose(nandFile);
        nandFile = NULL;
    }
}
