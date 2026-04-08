/*
 * FocalTech FTE4800 SPI fingerprint sensor driver for libfprint
 *
 * FTE4800 is a power-button-integrated capacitive sensor on SPI bus,
 * found in e.g. CHUWI ZeroBook 13 (ACPI: _SB.PC00.SPI2.FPNT, chip FT9368/FT9369).
 *
 * Copyright (C) 2024 The libfprint contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#pragma once

#include <fp-image-device.h>
#include <fpi-image-device.h>
#include <fpi-device.h>

G_DECLARE_FINAL_TYPE (FpiDeviceFte4800, fpi_device_fte4800, FPI, DEVICE_FTE4800, FpImageDevice)

/* ------------------------------------------------------------------ */
/* ACPI / udev matching                                                */
/* ------------------------------------------------------------------ */

#define FTE4800_UDEV_TYPES  FPI_DEVICE_UDEV_SUBTYPE_SPIDEV

/* ------------------------------------------------------------------ */
/* SPI protocol constants (reverse-engineered from ftWbioUmdfDriverV2) */
/* ------------------------------------------------------------------ */

/*
 * Wire format (MSB-first, CPOL=0 CPHA=0, all commands satisfy byte0+byte1=0xFF):
 *
 *  Wakeup:      TX [0xFF 0x00 0x00 0x00]                      (4 B, no RX)
 *  Mode cmd:    TX [cmd  ~cmd 0x00]                           (3 B, no RX)
 *  Read 8-bit:  TX [0x08 0xF7 reg8  0x00 0x00]               (5 B) + RX 1 B
 *  Read 16-bit: TX [0x04 0xFB hi|0x80 lo 0x00 0x01]          (6 B) + RX 2 B BE
 *  FIFO read:   TX [0x06 0xF9 hi|0x80 lo cnt_hi cnt_lo]       (6 B) + RX cnt B
 *  Write 16-bit:TX [0x05 0xFA hi|0x80 lo 0x00 0x01 v_hi v_lo](8 B, no RX)
 *
 * Protocol confirmed from static analysis of DLL functions:
 *   0x180018024  SPI0_Read8  (single-byte register read)
 *   0x1800180c8  SPI0_Read16 (two-byte register read, big-endian result)
 *   0x180018274  SPI0_Write16
 *   0x1800183e0  mode_switch (3-byte mode command from mode table)
 *   0x180017e00  fw9369_fifo_read (bulk FIFO read for image data)
 *
 * Mode table (3 bytes each, from DLL .rdata at VA 0x180034c00):
 *   mode  0 (idle/stop):     0xC0 0x3F 0x00
 *   mode  3 (image scan):    0xC4 0x3B 0x00
 *   mode  9 (FDT down):      0x5A 0xA5 0x00
 *   mode 10 (FDT up):        0xA5 0x5A 0x00
 *   mode 11 (soft reset):    0x70 0x00 0x00
 */

/* Wakeup sequence first byte */
#define FTE4800_WAKEUP_BYTE   0xFF

/* Command bytes (byte0 + byte1 = 0xFF always) */
#define FTE4800_CMD_READ8     0x08   /* complement 0xF7 */
#define FTE4800_CMD_READ16    0x04   /* complement 0xFB */
#define FTE4800_CMD_FIFO      0x06   /* complement 0xF9 */
#define FTE4800_CMD_WRITE16   0x05   /* complement 0xFA */
#define FTE4800_CMD_WRITE8    0x09   /* complement 0xF6 — confirmed from DLL SPI_Write8 VA 0x180018080 */

/* Mode commands (3 bytes: [cmd, ~cmd, 0x00]) */
#define FTE4800_MODE_IDLE_0   0xC0   /* mode 0: idle/stop */
#define FTE4800_MODE_IMG_SCAN 0xC4   /* mode 3: image scan */
#define FTE4800_MODE_FDT_DN   0x5A   /* mode 9: FDT finger-down detect */
#define FTE4800_MODE_FDT_UP   0xA5   /* mode 10: FDT finger-up detect */
#define FTE4800_MODE_RESET    0x70   /* mode 11: soft reset (only 1 valid byte) */

/* Header / packet lengths in bytes */
#define FTE4800_WAKEUP_LEN    4
#define FTE4800_MODE_LEN      3
#define FTE4800_RD8_HDR_LEN   5
#define FTE4800_RD16_HDR_LEN  6
#define FTE4800_FIFO_HDR_LEN  6
#define FTE4800_WR16_LEN      8
#define FTE4800_WR8_LEN       4   /* write8: [0x09, 0xF6, reg, val] — 4 bytes, no RX */

/* ------------------------------------------------------------------ */
/* Register map (from Ghidra analysis of ftWbioUmdfDriverV2.dll)      */
/* ------------------------------------------------------------------ */

/* 8-bit registers (use read8 / write8 protocol) */
#define FTE4800_REG8_STATUS   0x80   /* work-mode status; 0x54 = image ready */
#define FTE4800_REG8_SYS_MODE 0xC6   /* system mode register */
#define FTE4800_REG8_GAIN     0xF1   /* gain/sensitivity — SPI_InitRegs arg (DLL VA 0x180017fe8) */
#define FTE4800_REG8_PLL      0xF4   /* PLL/clock config — SPI_InitRegs toggles 0xC0/C1/C0/C0 */
#define FTE4800_REG8_CAL      0xF3   /* calibration result read — returned by SPI_InitRegs */

/* 16-bit registers (use read16 / write16 protocol) */
#define FTE4800_REG16_CHIP_ID   0x85C0   /* chip ID (FT9368 family) */
#define FTE4800_REG16_ALT_ID    0x1A8B   /* alternate ID (expected 0x9362) */
#define FTE4800_REG16_SCAN_CFG  0x1800   /* scan configuration (written 0x4FFE) */
#define FTE4800_REG16_FDT_CFG   0x1801   /* FDT configuration */
#define FTE4800_REG16_DAC_A     0x1806   /* DAC / baseline A */
#define FTE4800_REG16_DAC_B     0x180A   /* DAC / baseline B */
#define FTE4800_REG16_DAC_C     0x180B   /* DAC / baseline C */
#define FTE4800_REG16_FDT_B     0x180C   /* FDT config B */
#define FTE4800_REG16_FDT_BASE  0xFC80   /* FDT baseline register address */

/*
 * FDT configuration value written to 0x1801 before each scan.
 * Derived via compute_func(0xFC80, 6, 0, cfg_byte):
 *   = (0xFC80 & 0xFF80) | (cfg_byte & 0x7F)
 *   DLL uses cfg_byte = 0xB9 (from global at 0x180147be4).
 *   FDT_VAL = 0xFC80 | (0xB9 & 0x7F) = 0xFC80 | 0x39 = 0xFCB9
 * Formula source: DLL VA 0x180010e3c reverse-engineered 2026-04-08.
 */
#define FTE4800_FDT_VAL_DEFAULT  0xFCB9

/* Status value in REG8_STATUS indicating image capture is ready */
#define FTE4800_STATUS_IMAGE_READY  0x54

/* ------------------------------------------------------------------ */
/* Image FIFO                                                          */
/* ------------------------------------------------------------------ */

/* Address of the image FIFO (from fw9369 image_read_bulk, fw9369_fifo_read) */
#define FTE4800_FIFO_ADDR     0x1A05

/*
 * Image dimensions: 10240 bytes total (0x2800) confirmed from image_read_bulk
 * (r14d = 0x2800).  80 × 128 = 10240 fits perfectly and matches typical
 * power-button fingerprint sensor proportions.
 */
#define FTE4800_IMG_WIDTH     80
#define FTE4800_IMG_HEIGHT    128
#define FTE4800_IMG_SIZE      (FTE4800_IMG_WIDTH * FTE4800_IMG_HEIGHT)   /* 10240 */

/* ------------------------------------------------------------------ */
/* Timing                                                              */
/* ------------------------------------------------------------------ */

/*
 * After wakeup, chip needs this long before accepting commands.
 * DLL sends wakeup then sleeps ~20ms before mode11 reset.
 */
#define FTE4800_WAKEUP_DELAY_USEC   (20 * 1000)

/*
 * After mode11 reset, chip needs time to process.
 * DLL sleeps ~100ms after mode11.
 */
#define FTE4800_RESET_DELAY_USEC    (100 * 1000)

/*
 * After mode0 (idle), chip needs settle time.
 * DLL sleeps ~50ms after mode0.
 */
#define FTE4800_MODE0_DELAY_USEC   (50 * 1000)

/* Delay between status polls while waiting for image ready (0x54). */
#define FTE4800_POLL_DELAY_USEC     (5 * 1000)

/*
 * Maximum polls waiting for image ready.
 * DLL (fw9369_img_scan_start VA 0x180016d52) polls EXACTLY 10 times then
 * proceeds unconditionally. We match this exactly.
 */
#define FTE4800_POLL_MAX_RETRIES    10

/*
 * SPI transfer timeout (in milliseconds).
 * Prevents hangs if chip doesn't respond.
 */
#define FTE4800_SPI_TIMEOUT_MS     500

/* ------------------------------------------------------------------ */
/* Device instance struct                                              */
/* ------------------------------------------------------------------ */

struct _FpiDeviceFte4800
{
  FpImageDevice parent;

  /* File descriptor for /dev/spidev* opened in img_open */
  int spi_fd;

  /* Values read during init */
  guint8  chip_id_hi;
  guint8  chip_id_lo;

  /* Scratch byte for 8-bit register reads */
  guint8  reg8_val;

  /* Scratch bytes for 16-bit register reads */
  guint8  reg16_buf[2];

  /* Image buffer for the in-progress capture */
  guint8 *image_buf;

  /* Poll retry counter */
  int poll_count;

  /* Set when deactivate was requested while a capture was in progress */
  gboolean deactivating;
  gboolean capturing;
};
