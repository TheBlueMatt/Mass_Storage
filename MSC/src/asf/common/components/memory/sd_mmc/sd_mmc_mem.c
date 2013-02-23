/**
 * \file
 *
 * \brief CTRL_ACCESS interface for common SD/MMC stack
 *
 * Copyright (c) 2012 Atmel Corporation. All rights reserved.
 *
 * \asf_license_start
 *
 * \page License
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The name of Atmel may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with an
 *    Atmel microcontroller product.
 *
 * THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * \asf_license_stop
 *
 */

#include <stdint.h>

/* User-configurable options */
#define READ_ONLY
#if 1 && defined(READ_ONLY)
#define USE_ARRAY
#endif

#define USE_ENCRYPTION
#ifdef USE_ENCRYPTION
#define CRYPT_START 0
static const unsigned char AES_KEY[16] = {0xff, 0xff, 0xff, 0xff,
										  0xff, 0xff, 0xff, 0xff,
										  0xff, 0xff, 0xff, 0xff,
										  0xff, 0xff, 0xff, 0xff};
// We use an IV of md5(block#) ^ AES_IV_XOR
// Though md5 highly broken, we are only using it to get mix data,
// and make no expectation that it is secure (as this code is public,
// and thus the use of it should be considered known by an attacker)
// We rely on the facts that AES_IV_XOR and AES_KEY are random and
// private for all security.
static const unsigned char AES_IV_XOR[16] = {0xff, 0xff, 0xff, 0xff,
											 0xff, 0xff, 0xff, 0xff,
											 0xff, 0xff, 0xff, 0xff,
											 0xff, 0xff, 0xff, 0xff};
#endif // USE_ENCRYPTION

#define CLEAR_ON_READ
#ifdef CLEAR_ON_READ
#define ERROR_FLAG_ON_CLEAR // Lights up the red LED when the clear condition has been met
#define BAD_START_SECTOR 10
#define OK_START_SECTOR 100
#define OK_END_SECTOR 1000
#define BAD_END_SECTOR 10000

// These bytes are written as-is to the cleared section, note that this makes obvious where the private section was,
// but its just as easy (probably easier) to just find which sectors where modified instead of looking for duplicate sectors.
static const uint8_t CLEAR_BYTES[512] = {
	0xb7, 0xd1, 0xc8, 0x34, 0x69, 0xb7, 0xca, 0x15, 0x45, 0x1b, 0xdd, 0x8b, 0x4e, 0x42, 0x9c, 0xa3,
	0xfe, 0x86, 0x6b, 0x2b, 0xae, 0x67, 0x89, 0xc0, 0x26, 0x5d, 0x05, 0x96, 0xd3, 0x23, 0x51, 0x5b,
	0xff, 0x4d, 0x14, 0xdd, 0xa4, 0xb3, 0x6f, 0xa5, 0xaa, 0xde, 0x23, 0xec, 0x05, 0x16, 0x59, 0x36,
	0xc6, 0x92, 0xb9, 0x80, 0xca, 0x5c, 0x21, 0x43, 0x83, 0x8a, 0xbf, 0xae, 0x37, 0x00, 0x94, 0xde,
	0x93, 0x7b, 0x31, 0x57, 0x03, 0xa7, 0xb3, 0xd9, 0x44, 0xef, 0xaf, 0x80, 0xc9, 0x3e, 0x1e, 0x03,
	0x0b, 0xb2, 0x79, 0xaa, 0x87, 0xdd, 0xa3, 0xb4, 0x80, 0x81, 0x46, 0x01, 0x8b, 0x52, 0xcf, 0x02,
	0x3f, 0x70, 0xcd, 0x39, 0x9b, 0x19, 0xa4, 0xf2, 0xff, 0xd7, 0xae, 0x89, 0xb9, 0x01, 0xb5, 0xa3,
	0x91, 0xd8, 0xcb, 0x7c, 0xbc, 0x40, 0x30, 0x4c, 0x42, 0x0f, 0x27, 0x24, 0x4b, 0xda, 0x7b, 0x2f,
	0x73, 0x52, 0xf4, 0x78, 0xaf, 0x32, 0x9c, 0xea, 0xcc, 0xcf, 0xa9, 0x83, 0x34, 0xe8, 0x3a, 0xfc,
	0x1e, 0xa2, 0xa1, 0x8a, 0xc0, 0x53, 0xcc, 0xb5, 0x8f, 0xd2, 0x85, 0x53, 0xdf, 0x49, 0x4b, 0x66,
	0x44, 0x69, 0x81, 0x3e, 0x9d, 0xd8, 0x7a, 0x8f, 0x46, 0x20, 0xad, 0xa5, 0x72, 0x01, 0xc9, 0xf8,
	0x83, 0x22, 0xf6, 0x0d, 0x1f, 0xe9, 0x28, 0x67, 0x49, 0xbe, 0x64, 0x27, 0xe4, 0x07, 0xc2, 0xf2,
	0x01, 0x7f, 0xa5, 0xec, 0x00, 0xa1, 0x09, 0xc5, 0xec, 0xe8, 0x1b, 0x27, 0xd5, 0x08, 0xa5, 0xa9,
	0xb3, 0xaf, 0xd2, 0x9c, 0x43, 0xfa, 0x27, 0xdb, 0x9a, 0x28, 0x9c, 0xe5, 0x72, 0x77, 0xb9, 0xed,
	0xb2, 0x50, 0x84, 0x1a, 0x32, 0x75, 0x0d, 0xce, 0x3d, 0x23, 0x8c, 0x27, 0xfa, 0x2f, 0xeb, 0xa9,
	0x06, 0xfa, 0xd4, 0x4d, 0x20, 0x8a, 0x30, 0x42, 0x19, 0x3c, 0xf5, 0x09, 0xce, 0x26, 0xa8, 0xe6,
	0x2c, 0x76, 0x6d, 0xeb, 0xf8, 0x9d, 0x3f, 0x25, 0x9a, 0x2e, 0x13, 0x85, 0x16, 0x90, 0x86, 0x5e,
	0xff, 0xa7, 0x8f, 0xf0, 0xcd, 0x67, 0xd7, 0xe6, 0x7e, 0xa7, 0x98, 0x8a, 0x17, 0x76, 0xc8, 0x1a,
	0xe0, 0x2f, 0xbc, 0xe5, 0x9f, 0xcf, 0xde, 0xe4, 0x8a, 0xf4, 0x1d, 0x0f, 0x80, 0xd4, 0x4a, 0xd4,
	0x37, 0xfc, 0xc8, 0x5e, 0xa5, 0x7e, 0x0e, 0x21, 0xdf, 0x88, 0x0f, 0xa9, 0xaa, 0x60, 0x6c, 0x5b,
	0x8b, 0xb8, 0x1e, 0xe4, 0xae, 0x49, 0x91, 0x64, 0x9e, 0x77, 0x89, 0xa0, 0x79, 0x91, 0x0c, 0x1f,
	0xd0, 0xe0, 0x32, 0xb1, 0x15, 0xb6, 0x54, 0x45, 0x17, 0x38, 0x5b, 0x9f, 0x3b, 0x3f, 0x04, 0x98,
	0x38, 0xed, 0x73, 0x4e, 0xdd, 0x6d, 0x92, 0x7b, 0x0c, 0x97, 0xae, 0xdc, 0xa2, 0xcb, 0x78, 0xb2,
	0x82, 0x32, 0xc2, 0x9b, 0xed, 0xea, 0x32, 0x0a, 0x45, 0x96, 0x98, 0xa3, 0x3e, 0x23, 0xe6, 0xc9,
	0xf1, 0xc9, 0x65, 0x46, 0xa8, 0x4c, 0x15, 0xbe, 0xda, 0xc9, 0xa7, 0x55, 0xbd, 0x9d, 0x6b, 0x15,
	0x42, 0xa1, 0x7f, 0xd5, 0x9b, 0x7f, 0x9b, 0x0c, 0x38, 0x40, 0xc4, 0x21, 0x29, 0x74, 0xef, 0x90,
	0x0a, 0xf8, 0x9c, 0x1e, 0x5e, 0x28, 0xcd, 0x61, 0xa9, 0xda, 0x53, 0x57, 0xf0, 0xa0, 0x1a, 0xbe,
	0x7a, 0x5c, 0x5d, 0xf9, 0x54, 0x7a, 0xe0, 0xe2, 0x49, 0x9d, 0xee, 0xea, 0x21, 0x89, 0xf2, 0x6e,
	0xc7, 0x85, 0x9a, 0x5f, 0x1d, 0x7d, 0x8f, 0x23, 0x2a, 0xef, 0x71, 0x6c, 0xa4, 0x64, 0x79, 0xd0,
	0x80, 0x95, 0x5d, 0x90, 0x71, 0xbd, 0xf3, 0x7c, 0x76, 0xed, 0x58, 0x80, 0x5a, 0xed, 0xdb, 0xf5,
	0xc7, 0x57, 0x3e, 0x18, 0x9a, 0xac, 0x7c, 0x56, 0x08, 0x42, 0xdc, 0x41, 0x37, 0x8a, 0x83, 0x76,
	0xb8, 0x1e, 0x5b, 0xfc, 0x1a, 0xcc, 0x78, 0x1a, 0x2d, 0xc3, 0x94, 0x8b, 0xdb, 0x92, 0x31, 0xe0
};

#endif // CLEAR_ON_READ

/* End user-configurable options */

#include "conf_access.h"

#if (SD_MMC_0_MEM == ENABLE) || (SD_MMC_1_MEM == ENABLE)

#include <string.h>
#include "conf_sd_mmc.h"
#include "sd_mmc.h"
#include "sd_mmc_mem.h"
#include "aes/aes.h"
#include "md5.h"
#ifdef USE_ARRAY
#include "array.h"
#endif

/**
 * \ingroup sd_mmc_stack_mem
 * \defgroup sd_mmc_stack_mem_internal Implementation of SD/MMC Memory
 * @{
 */

/**
 * \name Control Interface
 * @{
 */

Ctrl_status sd_mmc_test_unit_ready(uint8_t slot)
{
	switch (sd_mmc_check(slot))
	{
	case SD_MMC_OK:
		if (sd_mmc_get_type(slot) & (CARD_TYPE_SD | CARD_TYPE_MMC)) {
			return CTRL_GOOD;
		}
		// It is not a memory card
		return CTRL_NO_PRESENT;

	case SD_MMC_INIT_ONGOING:
		return CTRL_BUSY;

	case SD_MMC_ERR_NO_CARD:
		return CTRL_NO_PRESENT;

	default:
		return CTRL_FAIL;
	}
}

Ctrl_status sd_mmc_test_unit_ready_0(void)
{
	return sd_mmc_test_unit_ready(0);
}


Ctrl_status sd_mmc_test_unit_ready_1(void)
{
	return sd_mmc_test_unit_ready(1);
}

Ctrl_status sd_mmc_read_capacity(uint8_t slot, uint32_t *nb_sector)
{
	// Return last sector address (-1)
	*nb_sector = (sd_mmc_get_capacity(slot) * 2) - 1;
	return sd_mmc_test_unit_ready(slot);
}

Ctrl_status sd_mmc_read_capacity_0(uint32_t *nb_sector)
{
	return sd_mmc_read_capacity(0, nb_sector);
}

Ctrl_status sd_mmc_read_capacity_1(uint32_t *nb_sector)
{
	return sd_mmc_read_capacity(1, nb_sector);
}

bool sd_mmc_wr_protect(uint8_t slot)
{
	return sd_mmc_is_write_protected(slot);
}

bool sd_mmc_wr_protect_0(void)
{
#ifdef READ_ONLY
	return true;
#else
	return false;
#endif
}

bool sd_mmc_wr_protect_1(void)
{
	return sd_mmc_wr_protect(1);
}

bool sd_mmc_removal(uint8_t slot)
{
	UNUSED(slot);
	return false;
}

bool sd_mmc_removal_0(void)
{
	return sd_mmc_removal(0);
}

bool sd_mmc_removal_1(void)
{
	return sd_mmc_removal(1);
}
//! @}

#if ACCESS_USB == true
/**
 * \name MEM <-> USB Interface
 * @{
 */

#include "udi_msc.h"

#ifdef CLEAR_ON_READ
bool was_cleared = false;
bool sd_mmc_usb_check_sector(uint32_t addr, uint16_t nb_sector); // You know what GCC, sometimes I don't want to prototype everything...
bool sd_mmc_usb_check_sector(uint32_t addr, uint16_t nb_sector) {
	if (unlikely(((addr + nb_sector >= BAD_START_SECTOR && addr < OK_START_SECTOR) ||
					(addr <= BAD_END_SECTOR && addr + nb_sector > OK_END_SECTOR)) &&
					!was_cleared)) {
		if (sd_mmc_init_write_blocks(0, OK_START_SECTOR, OK_END_SECTOR-OK_START_SECTOR + 1) != SD_MMC_OK)
			return false;

		for (uint16_t i = 0; i <= OK_END_SECTOR-OK_START_SECTOR; i++) {
			if (SD_MMC_OK != sd_mmc_start_write_blocks(CLEAR_BYTES, 1))
				return false;

			if (SD_MMC_OK != sd_mmc_wait_end_of_write_blocks())
				return false;
		}
		was_cleared = true;
#ifdef ERROR_FLAG_ON_CLEAR
		ui_set_errorflag();
#endif
	}
	return true;
}
#endif // CLEAR_ON_READ

COMPILER_WORD_ALIGNED
uint8_t sector_buf_0[SD_MMC_BLOCK_SIZE];

COMPILER_WORD_ALIGNED
uint8_t sector_buf_1[SD_MMC_BLOCK_SIZE];

COMPILER_WORD_ALIGNED
uint8_t aes_buf[SD_MMC_BLOCK_SIZE];

Ctrl_status sd_mmc_usb_read_10(uint8_t slot, uint32_t addr, uint16_t nb_sector)
{
	bool b_first_step = true;
	uint16_t nb_step;
	aes_decrypt_ctx aes_ctx[1];
	MD5_CTX md5_ctx;
	unsigned char IV[16];
	
	if (!sd_mmc_usb_check_sector(addr, nb_sector))
		return CTRL_FAIL;

	switch (sd_mmc_init_read_blocks(slot, addr, nb_sector)) {
	case SD_MMC_OK:
		break;
	case SD_MMC_ERR_NO_CARD:
		return CTRL_NO_PRESENT;
	default:
		return CTRL_FAIL;
	}
	// Pipeline the 2 transfer in order to speed-up the performances
	nb_step = nb_sector + 1;
	while (nb_step--) {
		if (nb_step) { // Skip last step
			// MCI -> RAM
			if (SD_MMC_OK != sd_mmc_start_read_blocks(((nb_step % 2) == 0) ?
					sector_buf_0 : sector_buf_1, 1)) {
				return CTRL_FAIL;
			}
		}
		if (!b_first_step) { // Skip first step
#ifdef USE_ENCRYPTION
			// Decrypt
			uint32_t sector = addr + nb_sector - nb_step - 1;
			if (sector >= CRYPT_START) {
				MD5_Init (&md5_ctx);
				MD5_Update (&md5_ctx, &sector, sizeof(uint32_t));
				MD5_Final (IV, &md5_ctx);
				for (uint16_t i = 0; i < sizeof(IV); i++)
					IV[i] ^= AES_IV_XOR[i];
				
				aes_decrypt_key128(AES_KEY, aes_ctx);
				aes_cbc_decrypt(((nb_step % 2) == 0) ? sector_buf_1 : sector_buf_0, aes_buf,
								SD_MMC_BLOCK_SIZE, IV, aes_ctx);
			}
#endif // USE_ENCRYPTION
			// RAM -> USB
			if (!udi_msc_trans_block(true,
#ifdef USE_ENCRYPTION
					sector >= CRYPT_START ? aes_buf :
#endif // USE_ENCRYPTION
					(((nb_step % 2) == 0) ? sector_buf_1 : sector_buf_0),
					SD_MMC_BLOCK_SIZE, NULL)) {
				return CTRL_FAIL;
			}
		} else {
			b_first_step = false;
		}
		if (nb_step) { // Skip last step
			if (SD_MMC_OK != sd_mmc_wait_end_of_read_blocks()) {
				return CTRL_FAIL;
			}
		}
		b_first_step = false;
	}
	return CTRL_GOOD;
}

Ctrl_status sd_mmc_usb_read_10_0(uint32_t addr, uint16_t nb_sector)
{
#ifdef USE_ARRAY
	while (addr < sizeof(first_bytes)/SD_MMC_BLOCK_SIZE && nb_sector) {
		memcpy(sector_buf_0, first_bytes + addr*SD_MMC_BLOCK_SIZE, SD_MMC_BLOCK_SIZE);
		if (!udi_msc_trans_block(true, sector_buf_0, SD_MMC_BLOCK_SIZE, NULL))
			return CTRL_FAIL;
		addr++;
		nb_sector--;
	}
	if (nb_sector == 0)
		return CTRL_GOOD;
	else
#endif // USE_ARRAY
		return sd_mmc_usb_read_10(0, addr, nb_sector);
}

Ctrl_status sd_mmc_usb_read_10_1(uint32_t addr, uint16_t nb_sector)
{
	return sd_mmc_usb_read_10(1, addr, nb_sector);
}

Ctrl_status sd_mmc_usb_write_10(uint8_t slot, uint32_t addr, uint16_t nb_sector)
{
	bool b_first_step = true;
	uint16_t nb_step;
#ifdef USE_ENCRYPTION
	aes_encrypt_ctx aes_ctx[1];
	MD5_CTX md5_ctx;
	unsigned char IV[16];
#endif // USE_ENCRYPTION

	switch (sd_mmc_init_write_blocks(slot, addr, nb_sector)) {
	case SD_MMC_OK:
		break;
	case SD_MMC_ERR_NO_CARD:
		return CTRL_NO_PRESENT;
	default:
		return CTRL_FAIL;
	}
	// Pipeline the 2 transfer in order to speed-up the performances
	nb_step = nb_sector + 1;
	while (nb_step--) {
		if (!b_first_step) { // Skip first step
			// RAM -> MCI
			if (SD_MMC_OK != sd_mmc_start_write_blocks(((nb_step % 2) == 0) ?
					sector_buf_0 : sector_buf_1, 1)) {
				return CTRL_FAIL;
			}
		}
		if (nb_step) { // Skip last step
#ifdef USE_ENCRYPTION
			uint32_t sector = addr + nb_sector - nb_step;
#endif // USE_ENCRYPTION
			// USB -> RAM
			if (!udi_msc_trans_block(false,
#ifdef USE_ENCRYPTION
					sector >= CRYPT_START ? aes_buf :
#endif // USE_ENCRYPTION
					(((nb_step % 2) == 0) ? sector_buf_1 : sector_buf_0),
					SD_MMC_BLOCK_SIZE, NULL)) {
				return CTRL_FAIL;
			}
#ifdef USE_ENCRYPTION
			// Encrypt
			if (sector >= CRYPT_START) {
				MD5_Init (&md5_ctx);
				MD5_Update (&md5_ctx, &sector, sizeof(uint32_t));
				MD5_Final (IV, &md5_ctx);
				for (uint16_t i = 0; i < sizeof(IV); i++)
					IV[i] ^= AES_IV_XOR[i];
				
				aes_encrypt_key128(AES_KEY, aes_ctx);
				aes_cbc_encrypt(aes_buf, ((nb_step % 2) == 0) ? sector_buf_1 : sector_buf_0,
								SD_MMC_BLOCK_SIZE, IV, aes_ctx);
			}
#endif // USE_ENCRYPTION
		}
		if (!b_first_step) { // Skip first step
			if (SD_MMC_OK != sd_mmc_wait_end_of_write_blocks()) {
				return CTRL_FAIL;
			}
		} else {
			b_first_step = false;
		}
	}
	return CTRL_GOOD;
}

Ctrl_status sd_mmc_usb_write_10_0(uint32_t addr, uint16_t nb_sector)
{
	return sd_mmc_usb_write_10(0, addr, nb_sector);
}

Ctrl_status sd_mmc_usb_write_10_1(uint32_t addr, uint16_t nb_sector)
{
	return sd_mmc_usb_write_10(1, addr, nb_sector);
}
//! @}
#endif // ACCESS_USB == true


#if ACCESS_MEM_TO_RAM == true
/**
 * \name MEM <-> RAM Interface
 * @{
 */
Ctrl_status sd_mmc_mem_2_ram(uint8_t slot, uint32_t addr, void *ram)
{
	switch (sd_mmc_init_read_blocks(slot, addr, 1)) {
	case SD_MMC_OK:
		break;
	case SD_MMC_ERR_NO_CARD:
		return CTRL_NO_PRESENT;
	default:
		return CTRL_FAIL;
	}
	if (SD_MMC_OK != sd_mmc_start_read_blocks(ram, 1)) {
		return CTRL_FAIL;
	}
	if (SD_MMC_OK != sd_mmc_wait_end_of_read_blocks()) {
		return CTRL_FAIL;
	}
	return CTRL_GOOD;
}

Ctrl_status sd_mmc_mem_2_ram_0(uint32_t addr, void *ram)
{
	return sd_mmc_mem_2_ram(0, addr, ram);
}

Ctrl_status sd_mmc_mem_2_ram_1(uint32_t addr, void *ram)
{
	return sd_mmc_mem_2_ram(1, addr, ram);
}

Ctrl_status sd_mmc_ram_2_mem(uint8_t slot, uint32_t addr, const void *ram)
{
	switch (sd_mmc_init_write_blocks(slot, addr, 1)) {
	case SD_MMC_OK:
		break;
	case SD_MMC_ERR_NO_CARD:
		return CTRL_NO_PRESENT;
	default:
		return CTRL_FAIL;
	}
	if (SD_MMC_OK != sd_mmc_start_write_blocks(ram, 1)) {
		return CTRL_FAIL;
	}
	if (SD_MMC_OK != sd_mmc_wait_end_of_write_blocks()) {
		return CTRL_FAIL;
	}
	return CTRL_GOOD;
}

Ctrl_status sd_mmc_ram_2_mem_0(uint32_t addr, const void *ram)
{
	return sd_mmc_ram_2_mem(0, addr, ram);
}

Ctrl_status sd_mmc_ram_2_mem_1(uint32_t addr, const void *ram)
{
	return sd_mmc_ram_2_mem(1, addr, ram);
}
//! @}

//! @}
#endif // ACCESS_MEM_TO_RAM == true

#endif // SD_MMC_0_MEM == ENABLE || SD_MMC_1_MEM == ENABLE
