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


/* User-configureable options */
#define READ_ONLY
#if 1 && defined(READ_ONLY)
#define USE_ARRAY
#endif

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

// User-defined options:
#define CRYPT_START 0
static const unsigned char AES_KEY[16] = {0xff, 0xff, 0xff, 0xff,
										  0xff, 0xff, 0xff, 0xff,
										  0xff, 0xff, 0xff, 0xff,
										  0xf, 0xff, 0xff, 0xff};
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
			// RAM -> USB
			if (!udi_msc_trans_block(true,
					sector < CRYPT_START ? (((nb_step % 2) == 0) ? sector_buf_1 : sector_buf_0) : aes_buf,
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
#endif
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
			// USB -> RAM
			if (!udi_msc_trans_block(false,
					((nb_step % 2) == 0) ?
					sector_buf_1 : sector_buf_0,
					SD_MMC_BLOCK_SIZE,
					NULL)) {
				return CTRL_FAIL;
			}
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
