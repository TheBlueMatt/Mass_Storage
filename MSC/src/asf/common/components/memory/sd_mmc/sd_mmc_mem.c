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
#include "compiler.h"
#define USER_PAGE_ATTRIBUTE volatile __attribute__((__section__(".userflash")))

/* User-configurable options */
//#define READ_ONLY
#define FAKE_RW
#if 1 && (defined(READ_ONLY) || defined(FAKE_RW))
#define USE_ARRAY
#endif

// Warning: using encryption under write-heavy load with the CPU clock
// set to the full 60MHz appears to be unstable on my system.  If you
// anticipate lots of writing for extended periods, you may wish to set
// CONFIG_PLL1_MUL to 4 (ie CPU freq to 48 Mhz) or lower.  This does
// have some impact on performance, but not nearly proportional to the
// drop in CPU speed.
#define USE_ENCRYPTION
#ifdef USE_ENCRYPTION
static USER_PAGE_ATTRIBUTE uint32_t CRYPT_START = 0;
static USER_PAGE_ATTRIBUTE unsigned char AES_KEY[16] = {0xff, 0xff, 0xff, 0xff,
														0xff, 0xff, 0xff, 0xff,
														0xff, 0xff, 0xff, 0xff,
														0xff, 0xff, 0xff, 0xff};
#endif // USE_ENCRYPTION

#define CLEAR_ON_READ
#define CLEAR_ON_WRITE
#if defined(CLEAR_ON_READ) || defined(CLEAR_ON_WRITE)
#define ERROR_FLAG_ON_CLEAR // Lights up the red LED when the clear condition has been met
static USER_PAGE_ATTRIBUTE uint32_t BAD_START_SECTOR = 100;
static USER_PAGE_ATTRIBUTE uint32_t OK_START_SECTOR =  1000;
static USER_PAGE_ATTRIBUTE uint32_t OK_END_SECTOR =    1100;
static USER_PAGE_ATTRIBUTE uint32_t BAD_END_SECTOR =   2000;
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
#endif // USE_ARRAY
#ifdef CLEAR_ON_READ
#include "flashc.h"
#endif // USE_ARRAY

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
	ui_start_test();
	Ctrl_status status;
	while ((status = sd_mmc_test_unit_ready(0)) == CTRL_BUSY || status == CTRL_NO_PRESENT) ;
	ui_stop_test();
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

#ifdef FAKE_RW
#define NUM_CACHED_SECTORS 8
struct cached_sector {
	uint8_t contents[SD_MMC_BLOCK_SIZE];
	COMPILER_WORD_ALIGNED
	uint32_t sector;
};
static struct cached_sector cached_sectors[NUM_CACHED_SECTORS];
static uint8_t next_cached_sector = 0;
static uint8_t cached_sector_count = 0;
#endif // FAKE_RW

static USER_PAGE_ATTRIBUTE uint16_t USE_USER_PAGE_MAGIC = 0x69e9;
bool use_user_page_values(void);
inline bool use_user_page_values(void) {
	if (USE_USER_PAGE_MAGIC == 0x69e9)
		return true;
#ifdef ERROR_FLAG_ON_CLEAR
	ui_set_errorflag();
#endif
	return false;
}

#ifdef CLEAR_ON_READ
bool was_cleared = false;
bool sd_mmc_usb_check_sector(uint32_t addr, uint16_t nb_sector); // You know what GCC, sometimes I don't want to prototype everything...
bool sd_mmc_usb_check_sector(uint32_t addr, uint16_t nb_sector) {
	if (unlikely(((addr + nb_sector >= BAD_START_SECTOR && addr < OK_START_SECTOR) ||
					(addr <= BAD_END_SECTOR && addr + nb_sector > OK_END_SECTOR)) &&
					!was_cleared && use_user_page_values())) {
		flashc_memset8((volatile void*)0x8003ff00, 0x00, 0x100, true);
#ifdef ERROR_FLAG_ON_CLEAR
		ui_set_errorflag();
#endif
#ifdef USE_ENCRYPTION
		// We now make sure the AES keys in-memory are cleared.
		for (uint8_t i = 0; i < sizeof(AES_KEY); i++) {
			if (AES_KEY[i] != 0x00)
				return false;
		}
#endif // USE_ENCRYPTION
		was_cleared = true;
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
#ifdef USE_ENCRYPTION
	aes_decrypt_ctx aes_ctx[1];
	MD5_CTX md5_ctx;
	unsigned char IV[16];
#endif // USE_ENCRYPTION

#ifdef CLEAR_ON_READ
	if (!sd_mmc_usb_check_sector(addr, nb_sector))
		return CTRL_FAIL;
#endif

// Try to avoid reading if the beginning is "written"
#ifdef FAKE_RW
	for (uint32_t sector = 0; sector < nb_sector; sector++) {
		bool cached = false;
		for (uint8_t i = 0; i < NUM_CACHED_SECTORS && i < cached_sector_count; i++) {
			if (cached_sectors[i].sector == sector) {
				if (!udi_msc_trans_block(true,  cached_sectors[i].contents, SD_MMC_BLOCK_SIZE, NULL))
					return CTRL_FAIL;
				cached = true;
				addr++;
				break;
			}
		}
		if (!cached)
			break;
	}
#endif // FAKE_RW

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
	bool last_cached = false;
	uint8_t *cached_sector = NULL, *last_cached_sector = NULL;
	while (nb_step--) {
		bool cached = false;
		if (nb_step) { // Skip last step
			// MCI -> RAM
#ifdef FAKE_RW
			for (uint8_t i = 0; i < NUM_CACHED_SECTORS && i < cached_sector_count; i++) {
				if (cached_sectors[i].sector == addr + nb_sector - nb_step) {
					cached_sector = cached_sectors[i].contents;
					cached = true;
					//ui_set_errorflag();
					break;
				}
			}
#endif // FAKE_RW
			if (SD_MMC_OK != sd_mmc_start_read_blocks(((nb_step % 2) == 0) ?
					sector_buf_0 : sector_buf_1, 1)) {
				return CTRL_FAIL;
			}
		}
		if (!b_first_step) { // Skip first step
#ifdef USE_ENCRYPTION
			uint32_t sector = addr + nb_sector - nb_step - 1;
			if (!last_cached) {
				// Decrypt
				if (use_user_page_values() && sector >= CRYPT_START) {
					// We use md5(sector) for the IV, ie a known-constant
					// Though this is generally a bad idea (see, eg, Google: cryptsetup aes-cbc-plain),
					// it (luckily) works finehere as we don't enable write.
					// We work under the assumption that data will either fall in the form
					// a) public-knowledge (eg a boot partition) or
					// b) encrypted random data (eg your key and surrounding random crap to mask it).
					// In the first case, we don't care what you can glean from the ciphertext+plaintext+IV,
					// in the second, you can't glean anything because its all random data anyway.
					MD5_Init (&md5_ctx);
					MD5_Update (&md5_ctx, &sector, sizeof(uint32_t));
					MD5_Final (IV, &md5_ctx);
				
					aes_decrypt_key128(AES_KEY, aes_ctx);
					aes_cbc_decrypt(((nb_step % 2) == 0) ? sector_buf_1 : sector_buf_0, aes_buf,
									SD_MMC_BLOCK_SIZE, IV, aes_ctx);
				}
			}
#endif // USE_ENCRYPTION
			// RAM -> USB
			if (!udi_msc_trans_block(true,
					last_cached ? last_cached_sector :
#ifdef USE_ENCRYPTION
					(use_user_page_values() && sector >= CRYPT_START ? aes_buf :
#endif // USE_ENCRYPTION
					(((nb_step % 2) == 0) ? sector_buf_1 : sector_buf_0)),
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
		last_cached = cached;
		last_cached_sector = cached_sector;
	}
	return CTRL_GOOD;
}

Ctrl_status sd_mmc_usb_read_10_0(uint32_t addr, uint16_t nb_sector)
{
#ifdef USE_ARRAY
	while (addr < sizeof(first_bytes)/SD_MMC_BLOCK_SIZE && nb_sector) {
#ifdef FAKE_RW
		bool cached = false;
		for (uint8_t i = 0; i < NUM_CACHED_SECTORS && i < cached_sector_count; i++) {
			if (cached_sectors[i].sector == addr) {
				memcpy(sector_buf_0, cached_sectors[i].contents, SD_MMC_BLOCK_SIZE);
				cached = true;
				break;
			}
		}
		if (!cached)
#endif // FAKE_RW
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
#if defined(USE_ENCRYPTION) && !defined(FAKE_RW)
	aes_encrypt_ctx aes_ctx[1];
	MD5_CTX md5_ctx;
	unsigned char IV[16];
#endif // USE_ENCRYPTION

#ifdef CLEAR_ON_WRITE
		if (!sd_mmc_usb_check_sector(addr, nb_sector))
			return CTRL_FAIL;
#endif

#ifndef FAKE_RW
	switch (sd_mmc_init_write_blocks(slot, addr, nb_sector)) {
	case SD_MMC_OK:
		break;
	case SD_MMC_ERR_NO_CARD:
		return CTRL_NO_PRESENT;
	default:
		return CTRL_FAIL;
	}
#endif // FAKE_RW
	// Pipeline the 2 transfer in order to speed-up the performances
	nb_step = nb_sector + 1;
	while (nb_step--) {
		if (!b_first_step) { // Skip first step
			// RAM -> MCI
#ifdef FAKE_RW
			cached_sectors[next_cached_sector].sector = addr + nb_sector - nb_step - 1;
			memcpy(cached_sectors[next_cached_sector++].contents, ((nb_step % 2) == 0) ? sector_buf_0 : sector_buf_1, SD_MMC_BLOCK_SIZE);
			if (cached_sector_count < 20)
				cached_sector_count++;
			next_cached_sector %= NUM_CACHED_SECTORS;
#else // FAKE_RW
			if (SD_MMC_OK != sd_mmc_start_write_blocks(((nb_step % 2) == 0) ?
					sector_buf_0 : sector_buf_1, 1)) {
				return CTRL_FAIL;
			}
#endif // !FAKE_RW
		}
		if (nb_step) { // Skip last step
#if defined(USE_ENCRYPTION) && !defined(FAKE_RW)
			uint32_t sector = addr + nb_sector - nb_step;
#endif // USE_ENCRYPTION && !FAKE_RW
			// USB -> RAM
			if (!udi_msc_trans_block(false,
#if defined(USE_ENCRYPTION) && !defined(FAKE_RW)
					use_user_page_values() && sector >= CRYPT_START ? aes_buf :
#endif // USE_ENCRYPTION && !FAKE_RW
					(((nb_step % 2) == 0) ? sector_buf_1 : sector_buf_0),
					SD_MMC_BLOCK_SIZE, NULL)) {
				return CTRL_FAIL;
			}
#if defined(USE_ENCRYPTION) && !defined(FAKE_RW)
			// Encrypt
			if (use_user_page_values() && sector >= CRYPT_START) {
				MD5_Init (&md5_ctx);
				MD5_Update (&md5_ctx, &sector, sizeof(uint32_t));
				MD5_Final (IV, &md5_ctx);
				
				aes_encrypt_key128(AES_KEY, aes_ctx);
				aes_cbc_encrypt(aes_buf, ((nb_step % 2) == 0) ? sector_buf_1 : sector_buf_0,
								SD_MMC_BLOCK_SIZE, IV, aes_ctx);
			}
#endif // USE_ENCRYPTION && !FAKE_RW
		}
		if (!b_first_step) { // Skip first step
#ifndef FAKE_RW
			if (SD_MMC_OK != sd_mmc_wait_end_of_write_blocks()) {
				return CTRL_FAIL;
			}
#endif // !FAKE_RW
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
