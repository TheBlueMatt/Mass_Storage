/**
 * \file
 *
 * \brief CTRL_ACCESS interface for the AT45DBX data flash driver.
 *
 * Copyright (c) 2011 Atmel Corporation. All rights reserved.
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


//_____  I N C L U D E S ___________________________________________________

#include "conf_access.h"


#if AT45DBX_MEM == ENABLE

#include "conf_at45dbx.h"
#include "at45dbx.h"
#include "at45dbx_mem.h"


//_____ D E F I N I T I O N S ______________________________________________

/*! \name Control Interface
 */
//! @{


Ctrl_status at45dbx_test_unit_ready(void)
{
	return (at45dbx_mem_check() == true) ? CTRL_GOOD : CTRL_NO_PRESENT;
}


Ctrl_status at45dbx_read_capacity(U32 *u32_nb_sector)
{
	*u32_nb_sector = (AT45DBX_MEM_CNT << (AT45DBX_MEM_SIZE - AT45DBX_SECTOR_BITS)) - 1;
	return CTRL_GOOD;
}


bool at45dbx_wr_protect(void)
{
	return false;
}


bool at45dbx_removal(void)
{
	return false;
}


//! @}


#if ACCESS_USB == true

#include "udi_msc.h"


/*! \name MEM <-> USB Interface
 */
//! @{


Ctrl_status at45dbx_usb_read_10(U32 addr, U16 nb_sector)
{
	if (addr + nb_sector > AT45DBX_MEM_CNT << (AT45DBX_MEM_SIZE - AT45DBX_SECTOR_BITS)){
		return CTRL_FAIL;
	}
	at45dbx_read_sector_open(addr);
	at45dbx_read_multiple_sector(nb_sector);
	at45dbx_read_close();
	return CTRL_GOOD;
}


void at45dbx_read_multiple_sector_callback(const void *psector)
{
	udi_msc_trans_block( true, (uint8_t*)psector, AT45DBX_SECTOR_SIZE, NULL);
}


Ctrl_status at45dbx_usb_write_10(U32 addr, U16 nb_sector)
{
	if (addr + nb_sector > AT45DBX_MEM_CNT << (AT45DBX_MEM_SIZE - AT45DBX_SECTOR_BITS)){
		return CTRL_FAIL;
	}

	at45dbx_write_sector_open(addr);
	at45dbx_write_multiple_sector(nb_sector);
	at45dbx_write_close();
	return CTRL_GOOD;
}


void at45dbx_write_multiple_sector_callback(void *psector)
{
	udi_msc_trans_block( false, (uint8_t*)psector, AT45DBX_SECTOR_SIZE, NULL);
}


//! @}

#endif  // ACCESS_USB == true


#if ACCESS_MEM_TO_RAM == true

/*! \name MEM <-> RAM Interface
 */
//! @{


Ctrl_status at45dbx_df_2_ram(U32 addr, void *ram)
{
	if (addr + 1 > AT45DBX_MEM_CNT << (AT45DBX_MEM_SIZE - AT45DBX_SECTOR_BITS)){
		return CTRL_FAIL;
	}
	at45dbx_read_sector_open(addr);
	at45dbx_read_sector_to_ram(ram);
	at45dbx_read_close();
	return CTRL_GOOD;
}


Ctrl_status at45dbx_ram_2_df(U32 addr, const void *ram)
{
	if (addr + 1 > AT45DBX_MEM_CNT << (AT45DBX_MEM_SIZE - AT45DBX_SECTOR_BITS)) {
		return CTRL_FAIL;
	}

	at45dbx_write_sector_open(addr);
	at45dbx_write_sector_from_ram(ram);
	at45dbx_write_close();
	return CTRL_GOOD;
}


//! @}

#endif  // ACCESS_MEM_TO_RAM == true


#endif  // AT45DBX_MEM == ENABLE
