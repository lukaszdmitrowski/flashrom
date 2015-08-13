/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2012 secunet Security Networks AG
 * (Written by Nico Huber <nico.huber@secunet.com> for secunet)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */
/**
 * @mainpage
 *
 * Have a look at the Modules section for a function reference.
 */

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "flash.h"
#include "programmer.h"
#include "libflashrom.h"

/**
 * @defgroup fl-general General
 * @{
 */

/** Pointer to log callback function. */
static fl_log_callback_t *fl_log_callback = NULL;

/**
 * @brief Initialize libflashrom.
 *
 * @param perform_selfcheck If not zero, perform a self check.
 * @return 0 on success
 */
int fl_init(const int perform_selfcheck)
{
	if (perform_selfcheck && selfcheck())
		return 1;
	myusec_calibrate_delay();
	return 0;
}

/**
 * @brief Shut down libflashrom.
 * @return 0 on success
 */
int fl_shutdown(void)
{
	return 0; /* TODO: nothing to do? */
}

/* TODO: fl_set_loglevel()? do we need it?
         For now, let the user decide in his callback. */

/**
 * @brief Set the log callback function.
 *
 * Set a callback function which will be invoked whenever libflashrom wants
 * to output messages. This allows frontends to do whatever they see fit with
 * such messages, e.g. write them to syslog, or to file, or print them in a
 * GUI window, etc.
 *
 * @param log_callback Pointer to the new log callback function.
 */
void fl_set_log_callback(fl_log_callback_t *const log_callback)
{
	fl_log_callback = log_callback;
}
/** @private */
int print(const enum msglevel level, const char *const fmt, ...)
{
	if (fl_log_callback) {
		int ret;
		va_list args;
		va_start(args, fmt);
		ret = fl_log_callback(level, fmt, args);
		va_end(args);
		return ret;
	}
	return 0;
}

/** @} */ /* end fl-general */



/**
 * @defgroup fl-query Querying
 * @{
 */

/**
 * @brief Returns flashrom version
 * @return Flashrom version
 */
const char *fl_version(void)
{
        return flashrom_version;
}

/**
 * @brief Returns a list of supported programmers
 * @return List of supported programmers
 */
const char **fl_supported_programmers(void)
{
        enum programmer p = 0;
        const char **supported_programmers = NULL;

        supported_programmers = malloc((PROGRAMMER_INVALID + 1) * sizeof(char*));
        if (!supported_programmers) {
                msg_gerr("Out of memory!");
        } else {
                for (; p < PROGRAMMER_INVALID; ++p) {
                        supported_programmers[p] = programmer_table[p].name;
                }
                supported_programmers[PROGRAMMER_INVALID] = NULL;
        }

        return supported_programmers;
}

/**
 * @brief Returns list of supported flash ROM chips
 * @return List of supported flash ROM chips
 */
fl_flashchip_info *fl_supported_flash_chips(void)
{
        int i = 0;
        fl_flashchip_info *flashchip_info = NULL;

        flashchip_info = malloc(flashchips_size * sizeof(fl_flashchip_info));
        if (!flashchip_info) {
                msg_gerr("Out of memory!");
        } else {
                for (; i < flashchips_size; ++i) {
                        flashchip_info[i].vendor = flashchips[i].vendor;
                        flashchip_info[i].name = flashchips[i].name;
                        flashchip_info[i].tested.erase = flashchips[i].tested.erase;
                        flashchip_info[i].tested.probe = flashchips[i].tested.probe;
                        flashchip_info[i].tested.read = flashchips[i].tested.read;
                        flashchip_info[i].tested.write = flashchips[i].tested.write;
                        flashchip_info[i].total_size = flashchips[i].total_size;
                }
        }

        return flashchip_info;
}

/**
 * @brief Returns list of supported mainboards
 * @return List of supported mainborads
 */
fl_board_info *fl_supported_boards(void)
{
        const struct board_info *binfo = boards_known;
        fl_board_info *supported_boards = NULL;
        int boards_known_size = 0;
        int i = 0;

        while ((binfo++)->vendor)
                ++boards_known_size;
        binfo = boards_known;
        /* add place for {0} */
        ++boards_known_size;

        supported_boards = malloc(boards_known_size * sizeof(fl_board_info));

        if (!supported_boards) {
                msg_gerr("Out of memory!");
        } else {
                for (; i < boards_known_size; ++i) {
                        supported_boards[i].vendor = binfo[i].vendor;
                        supported_boards[i].name = binfo[i].name;
                        supported_boards[i].working = binfo[i].working;
                }
        }

        return supported_boards;
}

/**
 * @brief Returns list of supported chipsets
 * @return List of supported chipsets
 */
fl_chipset_info *fl_supported_chipsets(void)
{
        const struct penable *chipset = chipset_enables;
        fl_chipset_info *supported_chipsets = NULL;
        int chipset_enbales_size = 0;
        int i = 0;

        while ((chipset++)->vendor_name)
                ++chipset_enbales_size;
        chipset = chipset_enables;
        /* add place for {0}*/
        ++chipset_enbales_size;

        supported_chipsets = malloc(chipset_enbales_size * sizeof(fl_chipset_info));

        if (!supported_chipsets) {
                msg_gerr("Out of memory!");
        } else {
                for (; i < chipset_enbales_size; ++i) {
                        supported_chipsets[i].vendor = chipset[i].vendor_name;
                        supported_chipsets[i].chipset = chipset[i].device_name;
                        supported_chipsets[i].status = chipset[i].status;
                }
        }

        return supported_chipsets;
}

/**
 * @brief Frees fl_*_info and string lists allocated by flashrom
 * @param Pointer to block of memory which should be freed
 * @return 0 on success
 *         1 on null pointer error
 */
int fl_data_free(void *const p)
{
        if (!p) {
                msg_gerr("Null pointer!");
                return 1;
        } else {
                free(p);
                return 0;
        }
}

/** @} */ /* end fl-query */



/**
 * @defgroup fl-prog Programmers
 * @{
 */

/**
 * @brief Initialize the specified programmer.
 *
 * @param prog_name Name of the programmer to initialize.
 * @param prog_param Pointer to programmer specific parameters.
 * @return 0 on success
 */
int fl_programmer_init(const char *const prog_name, const char *const prog_param)
{
	unsigned prog;

	for (prog = 0; prog < PROGRAMMER_INVALID; prog++) {
		if (strcmp(prog_name, programmer_table[prog].name) == 0)
			break;
	}
	if (prog >= PROGRAMMER_INVALID) {
		msg_ginfo("Error: Unknown programmer \"%s\". Valid choices are:\n", prog_name);
		list_programmers_linebreak(0, 80, 0);
		return 1;
	}
	return programmer_init(prog, prog_param);
}

/**
 * @brief Shut down the initialized programmer.
 *
 * @return 0 on success
 */
int fl_programmer_shutdown(void)
{
	return programmer_shutdown();
}

/* TODO: fl_programmer_capabilities()? */

/** @} */ /* end fl-prog */



/**
 * @defgroup fl-flash Flash chips
 * @{
 */

/**
 * @brief Probe for a flash chip.
 *
 * Probes for a flash chip and returns a flash context, that can be used
 * later with flash chip and @ref fl-ops "image operations", if exactly one
 * matching chip is found.
 *
 * @param[out] flashctx Points to a pointer of type fl_flashctx_t that will
 *                      be set if exactly one chip is found. *flashctx has
 *                      to be freed by the caller with @ref fl_flash_release.
 * @param[in] chip_name Name of a chip to probe for, or NULL to probe for
 *                      all known chips.
 * @return 0 on success,
 *         3 if multiple chips were found,
 *         2 if no chip was found,
 *         or 1 on any other error.
 */
int fl_flash_probe(fl_flashctx_t **const flashctx, const char *const chip_name)
{
	int i, ret = 2;
	fl_flashctx_t second_flashctx = { 0, };

	chip_to_probe = chip_name; /* chip_to_probe is global in flashrom.c */

	*flashctx = malloc(sizeof(**flashctx));
	if (!*flashctx)
		return 1;
	memset(*flashctx, 0, sizeof(**flashctx));

	for (i = 0; i < registered_master_count; ++i) {
		int flash_idx = -1;
		if (!ret || (flash_idx = probe_flash(&registered_masters[i], 0, *flashctx, 0)) != -1) {
			ret = 0;
			/* We found one chip, now check that there is no second match. */
			if (probe_flash(&registered_masters[i], flash_idx + 1, &second_flashctx, 0) != -1) {
				ret = 3;
				break;
			}
		}
	}
	if (ret) {
		free(*flashctx);
		*flashctx = NULL;
	}
	return ret;
}

/**
 * @brief Returns string list of multiple chips found
 *
 * Probes for all known flash chips and returns string list of found chips.
 * Should be used only when multiple chips were found by fl_flash_probe
 *
 * @param[out] pointer to integer - filled by a number of found chips
 * @return String list of multiple chips found
 */
const char** fl_multiple_flash_probe(int *chip_count)
{
        const char **chip_names = NULL;
        struct flashctx flashes[6] = {{0}};
        int chip_index = 0;
        int i = 0;

        chip_to_probe = NULL;
        *chip_count = 0;

        while (*chip_count < ARRAY_SIZE(flashes)) {
                chip_index = probe_flash(&registered_masters[i], chip_index,
                                         &flashes[*chip_count], 0);
                if (chip_index == -1)
                        break;
                ++chip_index;
                ++(*chip_count);
        }

        chip_names = malloc((*chip_count) * sizeof(char*));

        if (!chip_names) {
                msg_gerr("Out of memory!");
        } else {
                for (; i < *chip_count; ++i) {
                        chip_names[i] = flashes[i].chip->name;
                }
        }

        return chip_names;
}

/**
 * @brief Returns the size of the specified flash chip in bytes.
 *
 * @param flashctx The queried flash context.
 * @return Size of flash chip in bytes.
 */
size_t fl_flash_getsize(const fl_flashctx_t *const flashctx)
{
	return flashctx->chip->total_size << 10;
}

/** @private */
int erase_and_write_flash(struct flashctx *flash, uint8_t *oldcontents, uint8_t *newcontents);
/** @private */
void emergency_help_message(void);
/**
 * @brief Erase the specified ROM chip.
 *
 * @param flashctx The context of the flash chip to erase.
 * @return 0 on success.
 */
int fl_flash_erase(fl_flashctx_t *const flashctx)
{
	const size_t flash_size = flashctx->chip->total_size * 1024;

	int ret = 0;

	uint8_t *const newcontents = malloc(flash_size);
	if (!newcontents) {
		msg_gerr("Out of memory!\n");
		return 1;
	}
	uint8_t *const oldcontents = malloc(flash_size);
	if (!oldcontents) {
		msg_gerr("Out of memory!\n");
		free(newcontents);
		return 1;
	}

	if (flashctx->chip->unlock)
		flashctx->chip->unlock(flashctx);

	/* Assume worst case for old contents: All bits are 0. */
	memset(oldcontents, 0x00, flash_size);
	/* Assume best case for new contents: All bits should be 1. */
	memset(newcontents, 0xff, flash_size);
	/* Side effect of the assumptions above: Default write action is erase
	 * because newcontents looks like a completely erased chip, and
	 * oldcontents being completely 0x00 means we have to erase everything
	 * before we can write.
	 */

	if (erase_and_write_flash(flashctx, oldcontents, newcontents)) {
		/* FIXME: Do we really want the scary warning if erase failed?
		 * After all, after erase the chip is either blank or partially
		 * blank or it has the old contents. A blank chip won't boot,
		 * so if the user wanted erase and reboots afterwards, the user
		 * knows very well that booting won't work.
		 */
		emergency_help_message();
		ret = 1;
	}

	free(oldcontents);
	free(newcontents);
	return ret;
}

/**
 * @brief Free a flash context.
 *
 * @param flashctx Flash context to free.
 */
void fl_flash_release(fl_flashctx_t *const flashctx)
{
	free(flashctx);
}

/** @} */ /* end fl-flash */



/**
 * @defgroup fl-ops Operations
 * @{
 */

/**
 * @brief Read the current image from the specified ROM chip.
 *
 * @param flashctx The context of the flash chip.
 * @param buffer Target buffer to write image to.
 * @param buffer_len Size of target buffer in bytes.
 * @return 0 on success,
 *         2 if buffer_len is to short for the flash chip's contents,
 *         or 1 on any other failure.
 */
int fl_image_read(fl_flashctx_t *const flashctx, void *const buffer, const size_t buffer_len)
{
	const size_t flash_size = flashctx->chip->total_size * 1024;

	int ret = 0;

	if (flashctx->chip->unlock)
		flashctx->chip->unlock(flashctx);

	msg_cinfo("Reading flash... ");
	if (flash_size > buffer_len) {
		msg_cerr("Buffer to short for this flash chip (%u < %u).\n",
			 (unsigned int)buffer_len, (unsigned int)flash_size);
		ret = 2;
		goto _out;
	}
	if (!flashctx->chip->read) {
		msg_cerr("No read function available for this flash chip.\n");
		ret = 1;
		goto _out;
	}
	if (flashctx->chip->read(flashctx, buffer, 0, flash_size)) {
		msg_cerr("Read operation failed!\n");
		ret = 1;
		goto _out;
	}
_out:
	msg_cinfo("%s.\n", ret ? "FAILED" : "done");
	return ret;
}

/** @private */
void nonfatal_help_message(void);
/**
 * @brief Write the specified image to the ROM chip.
 *
 * @param flashctx The context of the flash chip.
 * @param buffer Source buffer to read image from.
 * @param buffer_len Size of source buffer in bytes.
 * @return 0 on success,
 *         4 if buffer_len doesn't match the size of the flash chip,
 *         3 if write was tried, but nothing has changed,
 *         2 if write was tried, but flash contents changed,
 *         or 1 on any other failure.
 */
int fl_image_write(fl_flashctx_t *const flashctx, void *const buffer, const size_t buffer_len)
{
	const size_t flash_size = flashctx->chip->total_size * 1024;

	int ret = 0;

	if (buffer_len != flash_size) {
		msg_cerr("Buffer size doesn't match size of flash chip (%u != %u)\n.",
			 (unsigned int)buffer_len, (unsigned int)flash_size);
		return 4;
	}

	uint8_t *const newcontents = buffer;
	uint8_t *const oldcontents = malloc(flash_size);
	if (!oldcontents) {
		msg_gerr("Out of memory!\n");
		return 1;
	}
	if (fl_image_read(flashctx, oldcontents, flash_size)) {
		ret = 1;
		goto _free_out;
	}

	build_new_image(flashctx, oldcontents, newcontents);

	if (erase_and_write_flash(flashctx, oldcontents, newcontents)) {
		msg_cerr("Uh oh. Erase/write failed. Checking if anything changed.\n");
		if (!flashctx->chip->read(flashctx, newcontents, 0, flash_size)) {
			if (!memcmp(oldcontents, newcontents, flash_size)) {
				msg_cinfo("Good. It seems nothing was changed.\n");
				nonfatal_help_message();
				ret = 3;
				goto _free_out;
			}
		}
		emergency_help_message();
		ret = 2;
		goto _free_out;
	}

_free_out:
	free(oldcontents);
	return ret;
}

/** @private */
int compare_range(uint8_t *wantbuf, uint8_t *havebuf, unsigned int start, unsigned int len);
/**
 * @brief Verify the ROM chip's contents with the specified image.
 *
 * @param flashctx The context of the flash chip.
 * @param buffer Source buffer to verify with.
 * @param buffer_len Size of source buffer in bytes.
 * @return 0 on success,
 *         2 if buffer_len doesn't match the size of the flash chip,
 *         or 1 on any other failure.
 */
int fl_image_verify(fl_flashctx_t *const flashctx, void *const buffer, const size_t buffer_len)
{
	const size_t flash_size = flashctx->chip->total_size * 1024;

	int ret = 0;

	if (buffer_len != flash_size) {
		msg_cerr("Buffer size doesn't match size of flash chip (%u != %u)\n.",
			 (unsigned int)buffer_len, (unsigned int)flash_size);
		return 2;
	}

	uint8_t *const newcontents = buffer;
	uint8_t *const oldcontents = malloc(flash_size);
	if (!oldcontents) {
		msg_gerr("Out of memory!\n");
		return 1;
	}
	if (fl_image_read(flashctx, oldcontents, flash_size)) {
		ret = 1;
		goto _free_out;
	}

	build_new_image(flashctx, oldcontents, newcontents);

	msg_cinfo("Verifying flash... ");

	ret = compare_range(newcontents, oldcontents, 0, flash_size);
	if (!ret)
		msg_cinfo("VERIFIED.\n");

_free_out:
	free(oldcontents);
	return ret;
}

/** @} */ /* end fl-ops */
