/*
 * FocalTech FTE4800 SPI fingerprint sensor driver for libfprint
 *
 * Sensor: FocalTech FTE4800 (silicon FT9368 / FT9369)
 * Bus:    SPI (ACPI path _SB.PC00.SPI2.FPNT, ACPI ID "FTE4800")
 * Host:   CHUWI ZeroBook 13 / Fedora 43
 *
 * Protocol fully reverse-engineered from ftWbioUmdfDriverV2.dll via
 * Ghidra + capstone static analysis.  Key findings (all from v2.2.3.79):
 *
 *   SPI0_Read8   (VA 0x180018024): TX=[0x08,0xF7,reg,0,0] + RX 1B
 *   SPI0_Read16  (VA 0x1800180c8): TX=[0x04,0xFB,hi|0x80,lo,0,1] + RX 2B BE
 *   SPI0_Write16 (VA 0x180018274): TX=[0x05,0xFA,hi|0x80,lo,0,1,vh,vl] (8B)
 *   mode_switch  (VA 0x1800183e0): mode-table look-up → 3-byte [cmd,~cmd,0]
 *   fifo_read    (VA 0x180017e00): TX=[0x06,0xF9,hi|0x80,lo,cnt_hi,cnt_lo]+RX
 *   SPI0_Wakeup  (VA 0x18001bc48): TX=[0xFF,0,0,0]
 *
 *   Capture status reg  0x80:  0x54 = image ready (fw9369_img_scan_start)
 *   Image FIFO addr    0x1A05:  10240 bytes total (image_read_bulk, r14d=0x2800)
 *   Image scan mode:   [0xC4,0x3B,0x00]  (mode table entry 3)
 *
 * Copyright (C) 2024 The libfprint contributors
 *
 * LGPL-2.1-or-later — see fte4800.h for full licence text.
 */

#define FP_COMPONENT "fte4800"

#include "drivers_api.h"
#include "fte4800.h"

#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <unistd.h>

G_DEFINE_TYPE (FpiDeviceFte4800, fpi_device_fte4800, FP_TYPE_IMAGE_DEVICE)

/* ================================================================== */
/* Device ID table                                                     */
/* ================================================================== */

static const FpIdEntry fte4800_id_table[] = {
  {
    .udev_types  = FTE4800_UDEV_TYPES,
    .spi_acpi_id = "FTE4800",
    .driver_data = 0,
  },
  { .udev_types = 0 }
};

/* ================================================================== */
/* SPI helpers — encode address for 16-bit / FIFO commands            */
/* ================================================================== */

/*
 * The 16-bit read, write, and FIFO commands all encode the address as:
 *   byte[2] = (addr >> 8) | 0x80   (high byte with MSB set)
 *   byte[3] = addr & 0xFF          (low byte)
 * This matches the computation in SPI0_Read16 / SPI0_Write16 / fifo_read.
 */
static inline guint8
addr_hi_enc (guint16 addr)
{
  return ((addr >> 8) & 0xFF) | 0x80;
}

static inline guint8
addr_lo_enc (guint16 addr)
{
  return addr & 0xFF;
}

/* ================================================================== */
/* SPI transfer builders                                               */
/* ================================================================== */

/*
 * fte4800_xfer_wakeup — [0xFF 0x00 0x00 0x00]  (no RX)
 */
static FpiSpiTransfer *
fte4800_xfer_wakeup (FpiDeviceFte4800 *self)
{
  FpiSpiTransfer *xfer = fpi_spi_transfer_new (FP_DEVICE (self), self->spi_fd);

  fpi_spi_transfer_write (xfer, FTE4800_WAKEUP_LEN);
  xfer->buffer_wr[0] = FTE4800_WAKEUP_BYTE;
  /* bytes 1-3 = 0x00 (already zeroed by libfprint) */
  return xfer;
}

/*
 * fte4800_xfer_mode — [cmd  ~cmd  0x00]  (no RX)  3-byte mode command.
 */
static FpiSpiTransfer *
fte4800_xfer_mode (FpiDeviceFte4800 *self, guint8 cmd)
{
  FpiSpiTransfer *xfer = fpi_spi_transfer_new (FP_DEVICE (self), self->spi_fd);

  fpi_spi_transfer_write (xfer, FTE4800_MODE_LEN);
  xfer->buffer_wr[0] = cmd;
  xfer->buffer_wr[1] = (guint8)(~cmd);
  xfer->buffer_wr[2] = 0x00;
  return xfer;
}

/*
 * fte4800_xfer_mode_reset — mode 11 soft reset, 1 byte only: [0x70]
 *
 * CRITICAL: Mode 11 is special — the DLL sends ONLY [0x70], not [0x70,0x8F,0x00].
 * Confirmed from DLL disassembly: single-byte TX, no complement, no trailing 0.
 */
static FpiSpiTransfer *
fte4800_xfer_mode_reset (FpiDeviceFte4800 *self)
{
  FpiSpiTransfer *xfer = fpi_spi_transfer_new (FP_DEVICE (self), self->spi_fd);

  fpi_spi_transfer_write (xfer, 1);
  xfer->buffer_wr[0] = FTE4800_MODE_RESET;   /* 0x70 */
  return xfer;
}

/*
 * fte4800_xfer_write8 — write a single byte to an 8-bit register.
 *
 * TX: [0x09  0xF6  reg  value]  (4 bytes, no RX)
 *
 * Confirmed from DLL SPI_Write8 (VA 0x180018080):
 *   Buffer layout: word[0]=0xF609 (LE → bytes 0x09,0xF6), byte[2]=reg, byte[3]=val
 *   Length = 4.  0x09 + 0xF6 = 0xFF checksum ✓
 *   Calling convention: cl = reg_addr, dl = value
 *
 * Used by SPI_InitRegs (VA 0x180017fe8) to configure gain (0xF1) and PLL (0xF4).
 */
static FpiSpiTransfer *
fte4800_xfer_write8 (FpiDeviceFte4800 *self, guint8 reg, guint8 value)
{
  FpiSpiTransfer *xfer = fpi_spi_transfer_new (FP_DEVICE (self), self->spi_fd);

  fpi_spi_transfer_write (xfer, FTE4800_WR8_LEN);   /* 4 bytes */
  xfer->buffer_wr[0] = FTE4800_CMD_WRITE8;           /* 0x09 */
  xfer->buffer_wr[1] = ~FTE4800_CMD_WRITE8;          /* 0xF6 */
  xfer->buffer_wr[2] = reg;
  xfer->buffer_wr[3] = value;
  return xfer;
}

/*
 * fte4800_xfer_read8 — read a single byte from an 8-bit register address.
 *
 * TX: [0x08  0xF7  reg  0x00  0x00]  (5 bytes)
 * RX: [byte]
 *
 * Mirrors SPI0_Read8 (DLL VA 0x180018024).
 */
static FpiSpiTransfer *
fte4800_xfer_read8 (FpiDeviceFte4800 *self, guint8 reg, guint8 *out)
{
  FpiSpiTransfer *xfer = fpi_spi_transfer_new (FP_DEVICE (self), self->spi_fd);

  fpi_spi_transfer_write (xfer, FTE4800_RD8_HDR_LEN);
  xfer->buffer_wr[0] = FTE4800_CMD_READ8;    /* 0x08 */
  xfer->buffer_wr[1] = ~FTE4800_CMD_READ8;   /* 0xF7 */
  xfer->buffer_wr[2] = reg;
  xfer->buffer_wr[3] = 0x00;
  xfer->buffer_wr[4] = 0x00;

  fpi_spi_transfer_read_full (xfer, out, 1, NULL);
  return xfer;
}

/*
 * fte4800_xfer_read16 — read a 16-bit register (big-endian, 2 bytes).
 *
 * TX: [0x04  0xFB  hi|0x80  lo  0x00  0x01]  (6 bytes)
 * RX: [hi_byte  lo_byte]  → value = (hi_byte << 8) | lo_byte
 *
 * Mirrors SPI0_Read16 (DLL VA 0x1800180c8).
 * Result stored in self->reg16_buf[0..1]; caller combines them.
 */
static FpiSpiTransfer *
fte4800_xfer_read16 (FpiDeviceFte4800 *self, guint16 addr)
{
  FpiSpiTransfer *xfer = fpi_spi_transfer_new (FP_DEVICE (self), self->spi_fd);

  fpi_spi_transfer_write (xfer, FTE4800_RD16_HDR_LEN);
  xfer->buffer_wr[0] = FTE4800_CMD_READ16;    /* 0x04 */
  xfer->buffer_wr[1] = ~FTE4800_CMD_READ16;   /* 0xFB */
  xfer->buffer_wr[2] = addr_hi_enc (addr);
  xfer->buffer_wr[3] = addr_lo_enc (addr);
  xfer->buffer_wr[4] = 0x00;
  xfer->buffer_wr[5] = 0x01;

  fpi_spi_transfer_read_full (xfer, self->reg16_buf, 2, NULL);
  return xfer;
}

/*
 * fte4800_xfer_write16 — write a 16-bit value to a 16-bit register.
 *
 * TX: [0x05  0xFA  hi|0x80  lo  0x00  0x01  val_hi  val_lo]  (8 bytes, no RX)
 *
 * Mirrors SPI0_Write16 (DLL VA 0x180018274).
 */
static FpiSpiTransfer *
fte4800_xfer_write16 (FpiDeviceFte4800 *self, guint16 addr, guint16 value)
{
  FpiSpiTransfer *xfer = fpi_spi_transfer_new (FP_DEVICE (self), self->spi_fd);

  fpi_spi_transfer_write (xfer, FTE4800_WR16_LEN);
  xfer->buffer_wr[0] = FTE4800_CMD_WRITE16;    /* 0x05 */
  xfer->buffer_wr[1] = ~FTE4800_CMD_WRITE16;   /* 0xFA */
  xfer->buffer_wr[2] = addr_hi_enc (addr);
  xfer->buffer_wr[3] = addr_lo_enc (addr);
  xfer->buffer_wr[4] = 0x00;
  xfer->buffer_wr[5] = 0x01;                   /* word count = 1 */
  xfer->buffer_wr[6] = (value >> 8) & 0xFF;    /* val_hi */
  xfer->buffer_wr[7] = value & 0xFF;            /* val_lo */
  return xfer;
}

/*
 * fte4800_xfer_read_fifo — bulk read from the image FIFO.
 *
 * TX: [0x06  0xF9  hi|0x80  lo  cnt_hi  cnt_lo]  (6 bytes)
 * RX: [cnt bytes of image data]
 *
 * Mirrors fw9369_fifo_read (DLL VA 0x180017e00).
 * The caller must have allocated buf with at least len bytes.
 */
static FpiSpiTransfer *
fte4800_xfer_read_fifo (FpiDeviceFte4800 *self,
                         guint16           addr,
                         guint8           *buf,
                         guint16           len)
{
  FpiSpiTransfer *xfer = fpi_spi_transfer_new (FP_DEVICE (self), self->spi_fd);

  /*
   * DLL fifo_read (VA 0x180017e00) uses COMPLEX encoding:
   *   - Address 0x1A05 → bytes [0xFF, 0x9A] (not [0x9A, 0x05]!)
   *   - Count 0x2800 → bytes [0xFF, 0x13] (not [0x14, 0x00]!)
   * The DLL builds: word[rsp+0x40] = 0xF906 (command)
   *                 word[rsp+0x42] = calculated address encoding
   *                 word[rsp+0x44] = calculated count encoding
   *
   * For address 0x1A05 with count 0x2800:
   *   DLL sends: [06, F9, FF, 9A, FF, 13]
   *   We send:   [06, F9, 9A, 05, 14, 00]
   *
   * Let's try DLL's encoding to see if it works better.
   */
  guint16 nwords = len / 2;
  fpi_spi_transfer_write (xfer, FTE4800_FIFO_HDR_LEN);
  xfer->buffer_wr[0] = FTE4800_CMD_FIFO;           /* 0x06 */
  xfer->buffer_wr[1] = ~FTE4800_CMD_FIFO;          /* 0xF9 */
  
  /* Try DLL's address encoding: (addr | 0x80FF) >> 8 | (addr << 8) */
  guint16 dll_addr_enc = ((addr | 0x80FF) >> 8) | (addr << 8);
  xfer->buffer_wr[2] = (dll_addr_enc >> 8) & 0xFF;
  xfer->buffer_wr[3] = dll_addr_enc & 0xFF;
  
  /* Try DLL's count encoding: complex calculation giving 0xFF13 for 0x2800 */
  guint16 dll_count_enc = 0xFF13;  /* DLL uses fixed value, not proportional to len */
  xfer->buffer_wr[4] = (dll_count_enc >> 8) & 0xFF;
  xfer->buffer_wr[5] = dll_count_enc & 0xFF;

  fpi_spi_transfer_read_full (xfer, buf, len, NULL);
  return xfer;
}

/* ================================================================== */
/* Initialisation state machine                                        */
/* ================================================================== */

/* Forward declaration for init_func1 check callback */
static void
fte4800_init_func1_check_cb (FpiSpiTransfer *transfer,
                               FpDevice       *dev,
                               gpointer        unused,
                               GError         *error);

enum fte4800_init_state {
  /* ── Phase 1: chip wake + reset ─────────────────────────────────── */
  FTE4800_INIT_WAKEUP,            /* wakeup [0xFF,0,0,0]               */
  FTE4800_INIT_SOFT_RESET,        /* mode 11: [0x70] — 1 byte          */
  FTE4800_INIT_MODE_IDLE,         /* mode 0:  [0xC0 0x3F 0x00]         */
  FTE4800_INIT_WAKEUP2,           /* second wakeup                      */

  /*
   * ── Phase 2: pre_hw_init — init_func_1 (mode9 → mode10) ──────────
   * DLL: pre_hw_init(ecx=0) at VA 0x18000fa90 calls init_func_1
   *      (mode9→mode10) BEFORE fw9369_hw_init (PLL calibration).
   * In the wrong order (PLL first), chip enters broadcast mode and
   * all register reads return spurious 0xCE/0xCA status bytes.
   */
  FTE4800_INIT_PRE_MODE9,         /* pre_hw_init: mode9 (FDT dn)        */
  FTE4800_INIT_PRE_CHECK,         /* pre_hw_init: read status            */
  FTE4800_INIT_PRE_FORCE,         /* pre_hw_init: mode0 if !0x50         */
  FTE4800_INIT_PRE_MODE10,        /* pre_hw_init: mode10 (FDT up)        */

  /*
   * ── Phase 3: fw9369_hw_init — PLL calibration ─────────────────────
   * DLL VA 0x180010900: SPI_InitRegs(0x03) then SPI_InitRegs(0x13).
   * Each call: write8(0xF1,gain) + 4× write8(0xF4,…) + read8(0xF3).
   * Chip must be in mode10 (FDT-up) when this runs.
   */
  FTE4800_INIT_INIT_REGS_A,       /* SPI_InitRegs(0x03): write8(0xF1, 0x03) */
  FTE4800_INIT_INIT_REGS_B,       /* write8(0xF4, 0xC0)                      */
  FTE4800_INIT_INIT_REGS_C,       /* write8(0xF4, 0xC1) — PLL toggle         */
  FTE4800_INIT_INIT_REGS_D,       /* write8(0xF4, 0xC0)                      */
  FTE4800_INIT_INIT_REGS_E,       /* write8(0xF4, 0xC0)                      */
  FTE4800_INIT_INIT_REGS_F,       /* SPI_InitRegs(0x13): write8(0xF1, 0x13)  */
  FTE4800_INIT_INIT_REGS_G,       /* write8(0xF4, 0xC0)                      */
  FTE4800_INIT_INIT_REGS_H,       /* write8(0xF4, 0xC1) — PLL toggle         */
  FTE4800_INIT_INIT_REGS_I,       /* write8(0xF4, 0xC0)                      */
  FTE4800_INIT_INIT_REGS_J,       /* write8(0xF4, 0xC0)                      */

  /* ── Phase 4: post-PLL startup writes ────────────────────────────── */
  FTE4800_INIT_WRITE_FIFO_CFG,    /* write16(0x1A84, 0xFFFF) — FIFO config  */
  FTE4800_INIT_READ_CHIP_ID,      /* read16(0x85C0) — verify chip ID         */
  FTE4800_INIT_WRITE_SCAN_CFG,    /* write16(0x1800, 0x4FFE)                 */
  FTE4800_INIT_NSTATES
};

static void
fte4800_init_ssm_handler (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceFte4800 *self = FPI_DEVICE_FTE4800 (dev);
  FpiSpiTransfer *xfer = NULL;
  guint16 chip_id;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case FTE4800_INIT_WAKEUP:
      fprintf(stderr, "FTE4800: INIT_WAKEUP\n");
      xfer = fte4800_xfer_wakeup (self);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_INIT_SOFT_RESET:
      fprintf(stderr, "FTE4800: INIT_SOFT_RESET\n");
      usleep (10 * 1000);
      usleep (10 * 1000);
      xfer = fte4800_xfer_mode_reset (self);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_INIT_MODE_IDLE:
      fp_dbg ("<init> idle mode [0xC0 0x3F 0x00]");
      usleep (20 * 1000);
      xfer = fte4800_xfer_mode (self, FTE4800_MODE_IDLE_0);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_INIT_WAKEUP2:
      fp_dbg ("<init> wakeup2");
      usleep (10 * 1000);
      xfer = fte4800_xfer_wakeup (self);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_INIT_PRE_MODE9:
      /*
       * pre_hw_init (DLL VA 0x18000fa90, ecx=0) → init_func_1 (VA 0x180010ce8):
       *   mode9 → read status → if != 0x50: mode0 → always mode10
       * This MUST run BEFORE PLL calibration (fw9369_hw_init).
       * Running PLL first causes chip to enter broadcast mode → all reads broken.
       */
      fp_dbg ("<init> pre_hw_init: mode9");
      xfer = fte4800_xfer_mode (self, FTE4800_MODE_FDT_DN);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_INIT_PRE_CHECK:
      xfer = fte4800_xfer_read8 (self, FTE4800_REG8_STATUS, &self->reg8_val);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fte4800_init_func1_check_cb, NULL);
      return;

    case FTE4800_INIT_PRE_FORCE:
      fp_dbg ("<init> pre_hw_init: mode0 (status=0x%02X != 0x50)", self->reg8_val);
      xfer = fte4800_xfer_mode (self, FTE4800_MODE_IDLE_0);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_INIT_PRE_MODE10:
      fp_dbg ("<init> pre_hw_init: mode10 (FDT finger-up)");
      xfer = fte4800_xfer_mode (self, FTE4800_MODE_FDT_UP);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_INIT_INIT_REGS_A:
      /* SPI_InitRegs(0x03): chip must be in mode10 when PLL calibration runs */
      fp_dbg ("<init> fw9369_hw_init: SPI_InitRegs(0x03) — write8(0xF1, 0x03)");
      xfer = fte4800_xfer_write8 (self, FTE4800_REG8_GAIN, 0x03);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_INIT_INIT_REGS_B:
      /*
       * Continue SPI_InitRegs(3): write8(0xF4, 0xC0) + read8(0xF3)
       * The DLL chains write8(0xF4, 0xC0) x3 + write8(0xF4, 0xC1) in sequence.
       * We submit write8(0xF4, 0xC0) and chain the rest via dedicated states.
       */
      fp_dbg ("<init> SPI_InitRegs(3) — write8(0xF4, 0xC0)");
      xfer = fte4800_xfer_write8 (self, FTE4800_REG8_PLL, 0xC0);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_INIT_INIT_REGS_C:
      fp_dbg ("<init> SPI_InitRegs(3) — write8(0xF4, 0xC1)");
      xfer = fte4800_xfer_write8 (self, FTE4800_REG8_PLL, 0xC1);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_INIT_INIT_REGS_D:
      fp_dbg ("<init> SPI_InitRegs(3) — write8(0xF4, 0xC0)");
      xfer = fte4800_xfer_write8 (self, FTE4800_REG8_PLL, 0xC0);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_INIT_INIT_REGS_E:
      fp_dbg ("<init> SPI_InitRegs(3) — write8(0xF4, 0xC0)");
      xfer = fte4800_xfer_write8 (self, FTE4800_REG8_PLL, 0xC0);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_INIT_INIT_REGS_F:
      /* SPI_InitRegs(0x13): gain register — starts second PLL calibration */
      fp_dbg ("<init> SPI_InitRegs(0x13) — write8(0xF1, 0x13)");
      xfer = fte4800_xfer_write8 (self, FTE4800_REG8_GAIN, 0x13);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_INIT_INIT_REGS_G:
      fp_dbg ("<init> SPI_InitRegs(0x13) — write8(0xF4, 0xC0)");
      xfer = fte4800_xfer_write8 (self, FTE4800_REG8_PLL, 0xC0);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_INIT_INIT_REGS_H:
      fp_dbg ("<init> SPI_InitRegs(0x13) — write8(0xF4, 0xC1)");
      xfer = fte4800_xfer_write8 (self, FTE4800_REG8_PLL, 0xC1);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_INIT_INIT_REGS_I:
      fp_dbg ("<init> SPI_InitRegs(0x13) — write8(0xF4, 0xC0)");
      xfer = fte4800_xfer_write8 (self, FTE4800_REG8_PLL, 0xC0);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_INIT_INIT_REGS_J:
      fp_dbg ("<init> SPI_InitRegs(0x13) — write8(0xF4, 0xC0) [final]");
      xfer = fte4800_xfer_write8 (self, FTE4800_REG8_PLL, 0xC0);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_INIT_WRITE_FIFO_CFG:
      /*
       * Startup FIFO configuration: write16(0x1A84, 0xFFFF).
       * Called in DLL startup chain (fw9369 main init VA ~0x18000fe71) with arg=0xffff.
       * This configures the FIFO before first scan.
       */
      fp_dbg ("<init> write16(0x1A84, 0xFFFF) — startup FIFO config");
      xfer = fte4800_xfer_write16 (self, 0x1A84, 0xFFFF);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_INIT_READ_CHIP_ID:
      fp_dbg ("<init> reading chip ID from reg16 0x%04X", FTE4800_REG16_CHIP_ID);
      xfer = fte4800_xfer_read16 (self, FTE4800_REG16_CHIP_ID);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_INIT_WRITE_SCAN_CFG:
      chip_id = ((guint16)self->reg16_buf[0] << 8) | self->reg16_buf[1];
      fp_dbg ("<init> chip_id=0x%04X; writing scan_cfg 0x%04X←0x4FFE",
              chip_id, FTE4800_REG16_SCAN_CFG);
      self->chip_id_hi = self->reg16_buf[0];
      self->chip_id_lo = self->reg16_buf[1];
      xfer = fte4800_xfer_write16 (self, FTE4800_REG16_SCAN_CFG, 0x4FFE);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fpi_ssm_spi_transfer_cb, NULL);
      return;

    default:
      g_assert_not_reached ();
    }
}

static void
fte4800_init_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceFte4800 *self = FPI_DEVICE_FTE4800 (dev);

  if (error)
    {
      fp_err ("<init> FAILED: %s", error->message);
      g_error_free (error);
      fpi_image_device_activate_complete (FP_IMAGE_DEVICE (dev), NULL);
      return;
    }

  guint16 chip_id = ((guint16)self->chip_id_hi << 8) | self->chip_id_lo;
  fp_dbg ("<init> COMPLETE: chip_id=0x%04X", chip_id);

  fpi_image_device_activate_complete (FP_IMAGE_DEVICE (dev), NULL);
}

static void
fte4800_init_func1_check_cb (FpiSpiTransfer *transfer,
                               FpDevice       *dev,
                               gpointer        unused,
                               GError         *error)
{
  FpiDeviceFte4800 *self = FPI_DEVICE_FTE4800 (dev);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  fp_dbg ("<init> pre_hw_init: reg8[0x80]=0x%02X (want 0x50 for FDT-up-ready)", self->reg8_val);

  if (self->reg8_val == 0x50)
    {
      /* FDT ready — skip mode0, go straight to mode10 */
      fpi_ssm_jump_to_state (transfer->ssm, FTE4800_INIT_PRE_MODE10);
    }
  else
    {
      /* Status != 0x50: do mode0 first, then mode10 */
      fpi_ssm_next_state (transfer->ssm);   /* → INIT_PRE_FORCE */
    }
}

/* ================================================================== */
/* Capture state machine                                               */
/* ================================================================== */

enum fte4800_capture_state {
  FTE4800_CAPT_WAKEUP,          /* wake chip before each capture attempt       */
  FTE4800_CAPT_FDT_DOWN,        /* img_mode_init: mode9 (FDT finger-down)      */
  FTE4800_CAPT_FDT_CHECK,       /* read status; decide path                    */
  FTE4800_CAPT_FDT_UP_FORCE,    /* mode0 (only if status != 0x50)              */
  FTE4800_CAPT_FDT_MODE10,      /* mode10: finger-up detect (always)           */
  FTE4800_CAPT_WRITE_FDT_REG,   /* write16(0x1801, FDT_val)                    */
  FTE4800_CAPT_WRITE_SCAN_ARM,  /* write16(0x1800, 0x4FFE)  arm scan           */
  FTE4800_CAPT_MODE_SCAN,       /* mode3: image scan [0xC4 0x3B 0x00]          */
  FTE4800_CAPT_WRITE_REG_180C,  /* DLL writes 0x180C - missing step            */
  FTE4800_CAPT_POLL_STATUS,     /* read status 0x80, wait for 0x54 (max 10x)   */
  FTE4800_CAPT_TRIGGER,         /* write16(0x1800, 0x4FFF) trigger uncondit.    */
  FTE4800_CAPT_READ_IMAGE,      /* check status before FIFO read              */
  FTE4800_CAPT_FIFO_READ,       /* actual FIFO read from 0x1A05               */
  FTE4800_CAPT_WAKEUP2,         /* wakeup before finger-lift check             */
  FTE4800_CAPT_MODE_FDT_UP,     /* FDT up detect mode for lift                 */
  FTE4800_CAPT_WAIT_LIFT,       /* poll 0x80 for finger-gone condition          */
  FTE4800_CAPT_NSTATES
};

/* Called after FDT mode9 to decide which path to take. */
static void
fte4800_fdt_check_cb (FpiSpiTransfer *transfer,
                       FpDevice       *dev,
                       gpointer        unused,
                       GError         *error)
{
  FpiDeviceFte4800 *self = FPI_DEVICE_FTE4800 (dev);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  fp_dbg ("<fdt_check> reg8[0x80]=0x%02X (want 0x50 for finger-up)", self->reg8_val);

  if (self->reg8_val == 0x50)
    {
      /* Finger already up — skip mode0, go straight to FDT_MODE10 */
      fpi_ssm_jump_to_state (transfer->ssm, FTE4800_CAPT_FDT_MODE10);
    }
  else
    {
      /* Status != 0x50: do mode0 then mode10 */
      fpi_ssm_next_state (transfer->ssm);   /* → FTE4800_CAPT_FDT_UP_FORCE */
    }
}

/* Called when the status poll read completes. */
static void
fte4800_poll_status_cb (FpiSpiTransfer *transfer,
                         FpDevice       *dev,
                         gpointer        unused,
                         GError         *error)
{
  FpiDeviceFte4800 *self = FPI_DEVICE_FTE4800 (dev);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  fp_dbg ("<poll> status=0x%02X (want 0x%02X)", self->reg8_val,
          FTE4800_STATUS_IMAGE_READY);

  if (self->reg8_val == FTE4800_STATUS_IMAGE_READY)
    {
      fp_dbg ("<poll> >>> FOUND 0x54 - IMAGE READY! <<<");
      fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), TRUE);
    }

  self->poll_count++;
  fprintf(stderr, "FTE4800: poll_count=%d max=%d\n", self->poll_count, FTE4800_POLL_MAX_RETRIES);
  if (self->poll_count >= FTE4800_POLL_MAX_RETRIES)
    {
      fprintf(stderr, "FTE4800: DONE POLLING - GOING TO TRIGGER\n");
      self->poll_count = 0;
      fpi_ssm_next_state (transfer->ssm);   /* → FTE4800_CAPT_TRIGGER */
    }
  else
    {
      /* Keep polling */
      fpi_ssm_jump_to_state (transfer->ssm, FTE4800_CAPT_POLL_STATUS);
    }
}

/* Called after reading status before FIFO read - to see if image is actually ready */
static void
fte4800_fifo_status_cb (FpiSpiTransfer *transfer,
                         FpDevice       *dev,
                         gpointer       unused,
                         GError         *error)
{
  FpiDeviceFte4800 *self = FPI_DEVICE_FTE4800 (dev);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  fprintf(stderr, "FTE4800: FIFO pre-check status = 0x%02X\n", self->reg8_val);
  
  /* Always proceed to FIFO read - DLL does unconditional read */
  fpi_ssm_next_state (transfer->ssm);  /* → FTE4800_CAPT_FIFO_READ */
}

/* Called when the image FIFO read completes. */
static void
fte4800_image_read_cb (FpiSpiTransfer *transfer,
                        FpDevice       *dev,
                        gpointer        unused,
                        GError         *error)
{
  FpiDeviceFte4800 *self = FPI_DEVICE_FTE4800 (dev);
  FpImageDevice *idev = FP_IMAGE_DEVICE (dev);

  if (error)
    {
      fprintf(stderr, "FTE4800: FIFO read ERROR: %s\n", error->message);
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  fprintf(stderr, "FTE4800: FIFO read SUCCESS! Calling image_captured\n");
  /* Hand the raw pixel buffer to libfprint. */
  FpImage *img = fp_image_new (FTE4800_IMG_WIDTH, FTE4800_IMG_HEIGHT);
  memcpy (img->data, self->image_buf, FTE4800_IMG_SIZE);
  g_clear_pointer (&self->image_buf, g_free);

  /*
   * Check the device state before calling image_captured.
   * Only call it if we're in CAPTURE state (finger was detected).
   * If state is AWAIT_FINGER_ON, the capture was too fast and we need to retry.
   * Based on egis0570 driver pattern.
   */
  {
    FpiImageDeviceState state;
    g_object_get (dev, "fpi-image-device-state", &state, NULL);
    fprintf(stderr, "FTE4800: image_read state=%d, forcing image_captured\n", state);
    int unique = 0;
    for (int i = 0; i < FTE4800_IMG_SIZE; i++) if (img->data[i] != 0) unique++;
    fprintf(stderr, "FTE4800: Image: %d/%d non-zero bytes\n", unique, FTE4800_IMG_SIZE);
    fprintf(stderr, "FTE4800: First 16 bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
        img->data[0], img->data[1], img->data[2], img->data[3],
        img->data[4], img->data[5], img->data[6], img->data[7],
        img->data[8], img->data[9], img->data[10], img->data[11],
        img->data[12], img->data[13], img->data[14], img->data[15]);
    fprintf(stderr, "FTE4800: >>> CALLING image_captured <<<\n");
    fpi_image_device_image_captured (idev, img);
  }
  fpi_ssm_next_state (transfer->ssm);  /* → CAPT_WAKEUP2 */
}

/* Called when the finger-lift status poll completes. */
static void
fte4800_lift_cb (FpiSpiTransfer *transfer,
                  FpDevice       *dev,
                  gpointer        unused,
                  GError         *error)
{
  FpiDeviceFte4800 *self = FPI_DEVICE_FTE4800 (dev);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  /*
   * After FDT-up mode, reg 0x80 returns something other than 0x54 when
   * the finger is removed.  Any value != 0x54 is treated as "lifted".
   * TODO: confirm the exact "lifted" status byte once known.
   */
  if (self->reg8_val != FTE4800_STATUS_IMAGE_READY)
    {
      fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), FALSE);
      fpi_ssm_mark_completed (transfer->ssm);
    }
  else
    {
      /* Finger still on sensor; keep polling */
      fpi_ssm_jump_to_state (transfer->ssm, FTE4800_CAPT_WAIT_LIFT);
    }
}

static void
fte4800_capture_ssm_handler (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceFte4800 *self = FPI_DEVICE_FTE4800 (dev);
  FpiSpiTransfer *xfer = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case FTE4800_CAPT_WAKEUP:
      fprintf(stderr, "FTE4800: CAPT_WAKEUP\n");
      xfer = fte4800_xfer_wakeup (self);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, fpi_device_get_cancellable (dev),
                                fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_CAPT_FDT_DOWN:
      fprintf(stderr, "FTE4800: CAPT_FDT_DOWN\n");
      fp_dbg ("<capture> FDT init: mode9");
      usleep (5 * 1000);
      self->poll_count = 0;
      xfer = fte4800_xfer_mode (self, FTE4800_MODE_FDT_DN);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, fpi_device_get_cancellable (dev),
                                fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_CAPT_FDT_CHECK:
      fprintf(stderr, "FTE4800: CAPT_FDT_CHECK (spi_fd=%d)\n", self->spi_fd);
      fp_dbg ("<capture> FDT check: reading status");
      usleep (2 * 1000);
      xfer = fte4800_xfer_read8 (self, FTE4800_REG8_STATUS, &self->reg8_val);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, fpi_device_get_cancellable (dev),
                                fte4800_fdt_check_cb, NULL);
      return;

    case FTE4800_CAPT_FDT_UP_FORCE:
      /*
       * Status was not 0x50 after mode9 — send mode0 (idle) first.
       * From init_func_0: mode0 only when status != 0x50.
       */
      fp_dbg ("<capture> FDT: mode0 (idle before mode10)");
      xfer = fte4800_xfer_mode (self, FTE4800_MODE_IDLE_0);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, fpi_device_get_cancellable (dev),
                                fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_CAPT_FDT_MODE10:
      fprintf(stderr, "FTE4800: CAPT_FDT_MODE10\n");
      xfer = fte4800_xfer_mode (self, FTE4800_MODE_FDT_UP);
      xfer = fte4800_xfer_mode (self, FTE4800_MODE_FDT_UP);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, fpi_device_get_cancellable (dev),
                                fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_CAPT_WRITE_FDT_REG:
      /*
       * write16(0x1801, FDT_val) — FDT configuration.
       * From img_mode_init (DLL VA 0x1800165f4):
       *   compute_func(0xFC80, 6, 0, cfg_byte) = 0xFC80 | (cfg_byte & 0x7F)
       *   DLL uses cfg_byte=0xB9, so FDT_VAL = 0xFCB9.
       */
      fp_dbg ("<capture> write16(0x1801, 0x%04X) [FDT config]", FTE4800_FDT_VAL_DEFAULT);
      xfer = fte4800_xfer_write16 (self, FTE4800_REG16_FDT_CFG, FTE4800_FDT_VAL_DEFAULT);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, fpi_device_get_cancellable (dev),
                                fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_CAPT_WRITE_SCAN_ARM:
      fprintf(stderr, "FTE4800: CAPT_WRITE_SCAN_ARM\n");
      fp_dbg ("<capture> arming scan: write16(0x1800, 0x4FFE)");
      xfer = fte4800_xfer_write16 (self, FTE4800_REG16_SCAN_CFG, 0x4FFE);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, fpi_device_get_cancellable (dev),
                                fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_CAPT_MODE_SCAN:
      fprintf(stderr, "FTE4800: CAPT_MODE_SCAN\n");
      fp_dbg ("<capture> >>> SENDING MODE3 (image scan) <<<");
      usleep (10 * 1000);
      xfer = fte4800_xfer_mode (self, FTE4800_MODE_IMG_SCAN);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, fpi_device_get_cancellable (dev),
                                fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_CAPT_WRITE_REG_180C:
      /*
       * DLL writes to 0x180C between mode3 and poll.
       * At 0x180012e2d: mov edi, 0x180c
       * At 0x180012e37: call write16(0x180c, computed_value)
       * The computed value comes from compute_func with various parameters.
       */
      fp_dbg ("<capture> DLL writes 0x180C - adding missing step");
      xfer = fte4800_xfer_write16 (self, 0x180C, 0x0006);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, fpi_device_get_cancellable (dev),
                                fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_CAPT_POLL_STATUS:
      fprintf(stderr, "FTE4800: CAPT_POLL_STATUS\n");
      fp_dbg ("<capture> poll status (retry %d/%d)", self->poll_count + 1,
             FTE4800_POLL_MAX_RETRIES);
      usleep (5 * 1000);
      xfer = fte4800_xfer_read8 (self, FTE4800_REG8_STATUS, &self->reg8_val);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, fpi_device_get_cancellable (dev),
                                fte4800_poll_status_cb, NULL);
      return;

    case FTE4800_CAPT_TRIGGER:
      fprintf(stderr, "FTE4800: CAPT_TRIGGER\n");
      fp_dbg ("<capture> trigger");
      /*
       * Unconditional trigger — mirrors img_scan_start (DLL VA 0x180016d62):
       *   v = read16(0x1800)
       *   v |= 0x0001           — compute_func(v, 0, 0, 1) = v | 1
       *   write16(0x1800, v)    — = 0x4FFE | 1 = 0x4FFF
       *   sleep_ms(1)
       *
       * This is done UNCONDITIONALLY after the poll loop, whether or not
       * 0x54 was seen.  The chip latches the capture on this write.
       */
      fprintf(stderr, "FTE4800: TRIGGER - sending write16(0x1800, 0x4FFF)\n");
      fp_dbg ("<capture> trigger: write16(0x1800, 0x4FFF)");
      xfer = fte4800_xfer_write16 (self, FTE4800_REG16_SCAN_CFG, 0x4FFF);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, fpi_device_get_cancellable (dev),
                                fpi_ssm_spi_transfer_cb, NULL);
      fprintf(stderr, "FTE4800: TRIGGER submitted, waiting...\n");
      fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), TRUE);
      return;

    case FTE4800_CAPT_READ_IMAGE:
      fprintf(stderr, "FTE4800: CAPT_READ_IMAGE reached!\n");
      /*
       * After trigger (write16 0x1800 = 0x4FFF), DLL sleeps 1ms before FIFO read.
       * Let's read status first to see if image is really ready.
       */
      fp_dbg ("<capture> checking status before FIFO read");
      usleep (1 * 1000);
      
      /* First read status to check if we actually got 0x54 */
      xfer = fte4800_xfer_read8 (self, FTE4800_REG8_STATUS, &self->reg8_val);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, fpi_device_get_cancellable (dev),
                                fte4800_fifo_status_cb, NULL);
      return;

    case FTE4800_CAPT_FIFO_READ:
      /* Status was checked, now do the actual FIFO read */
      fprintf(stderr, "FTE4800: CAPT_FIFO_READ - status was 0x%02X\n", self->reg8_val);
      fp_dbg ("<capture> reading %u bytes from FIFO addr 0x%04X",
              FTE4800_IMG_SIZE, FTE4800_FIFO_ADDR);
      g_clear_pointer (&self->image_buf, g_free);
      self->image_buf = g_malloc (FTE4800_IMG_SIZE);
      xfer = fte4800_xfer_read_fifo (self, FTE4800_FIFO_ADDR,
                                      self->image_buf, FTE4800_IMG_SIZE);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fte4800_image_read_cb, NULL);
      fprintf(stderr, "FTE4800: FIFO read submitted (waiting for image)\n");
      return;

    case FTE4800_CAPT_WAKEUP2:
      /* Wakeup before checking finger lift */
      xfer = fte4800_xfer_wakeup (self);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_CAPT_MODE_FDT_UP:
      /* FDT finger-up detect: [0xA5, 0x5A, 0x00] */
      xfer = fte4800_xfer_mode (self, FTE4800_MODE_FDT_UP);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fpi_ssm_spi_transfer_cb, NULL);
      return;

    case FTE4800_CAPT_WAIT_LIFT:
      xfer = fte4800_xfer_read8 (self, FTE4800_REG8_STATUS, &self->reg8_val);
      xfer->ssm = ssm;
      fpi_spi_transfer_submit (xfer, NULL, fte4800_lift_cb, NULL);
      return;

    default:
      g_assert_not_reached ();
    }
}

static void
fte4800_capture_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceFte4800 *self = FPI_DEVICE_FTE4800 (dev);
  FpImageDevice *idev = FP_IMAGE_DEVICE (dev);

  self->capturing = FALSE;
  g_clear_pointer (&self->image_buf, g_free);

  if (error)
    {
      fp_err ("<capture> FAILED: %s", error->message);
      fpi_image_device_session_error (idev, error);
      return;
    }

  fp_dbg ("<capture> SSM completed successfully");
}

/* ================================================================== */
/* FpImageDevice vfunc implementations                                */
/* ================================================================== */

#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>

static void
fte4800_img_open (FpImageDevice *dev)
{
  FpiDeviceFte4800 *self = FPI_DEVICE_FTE4800 (dev);
  GError *err = NULL;
  guint32 spi_mode = 0;
  guint32 spi_speed = 1000000;

  G_DEBUG_HERE ();
  fp_dbg ("<open> opening SPI device");

  const char *spidev_path = fpi_device_get_udev_data (FP_DEVICE (dev),
                                                        FPI_DEVICE_UDEV_SUBTYPE_SPIDEV);
  int spi_fd = open (spidev_path, O_RDWR);

  if (spi_fd < 0)
    {
      g_set_error (&err, G_IO_ERROR, g_io_error_from_errno (errno),
                   "unable to open spidev %s: %s", spidev_path, g_strerror (errno));
      fp_err ("<open> failed to open %s: %s", spidev_path, g_strerror (errno));
      fpi_image_device_open_complete (dev, err);
      return;
    }

  fp_dbg ("<open> opened %s, fd=%d", spidev_path, spi_fd);

  if (ioctl (spi_fd, SPI_IOC_WR_MODE32, &spi_mode) < 0)
    g_debug ("<open> could not set SPI mode: %s", g_strerror (errno));
  else
    fp_dbg ("<open> SPI mode set to %u (CPOL=%u CPHA=%u)", spi_mode,
           (spi_mode >> 1) & 1, spi_mode & 1);

  if (ioctl (spi_fd, SPI_IOC_WR_MAX_SPEED_HZ, &spi_speed) < 0)
    g_debug ("<open> could not set SPI speed: %s", g_strerror (errno));
  else
    fp_dbg ("<open> SPI speed set to %u Hz", spi_speed);

  self->spi_fd = spi_fd;
  fpi_image_device_open_complete (dev, NULL);
}

static void
fte4800_img_close (FpImageDevice *dev)
{
  FpiDeviceFte4800 *self = FPI_DEVICE_FTE4800 (dev);

  G_DEBUG_HERE ();

  if (self->spi_fd >= 0)
    {
      close (self->spi_fd);
      self->spi_fd = -1;
    }
  fpi_image_device_close_complete (dev, NULL);
}

static void
fte4800_activate (FpImageDevice *dev)
{
  FpiDeviceFte4800 *self = FPI_DEVICE_FTE4800 (dev);

  G_DEBUG_HERE ();
  fp_dbg ("<activate> starting, spi_fd=%d", self->spi_fd);

  FpiSsm *ssm = fpi_ssm_new (FP_DEVICE (dev),
                               fte4800_init_ssm_handler,
                               FTE4800_INIT_NSTATES);
  fp_dbg ("<activate> init SSM created, starting...");
  fpi_ssm_start (ssm, fte4800_init_ssm_done);
}

static void
fte4800_deactivate (FpImageDevice *dev)
{
  FpiDeviceFte4800 *self = FPI_DEVICE_FTE4800 (dev);

  G_DEBUG_HERE ();

  if (self->capturing)
    {
      self->deactivating = TRUE;
      fp_dbg ("<deactivate> capture in progress, deferring");
    }
  else
    {
      fpi_image_device_deactivate_complete (dev, NULL);
    }
}

static void
fte4800_change_state (FpImageDevice *dev, FpiImageDeviceState state)
{
  FpiDeviceFte4800 *self = FPI_DEVICE_FTE4800 (dev);

  fp_dbg ("<change_state> new state=%d", state);

  if (state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON)
    {
      g_assert (!self->capturing);
      self->capturing = TRUE;
      self->poll_count = 0;

      fp_dbg ("<change_state> starting capture SSM...");
      FpiSsm *ssm = fpi_ssm_new (FP_DEVICE (dev),
                                   fte4800_capture_ssm_handler,
                                   FTE4800_CAPT_NSTATES);
      fpi_ssm_start (ssm, fte4800_capture_ssm_done);
    }
}

/* ================================================================== */
/* GObject boilerplate                                                 */
/* ================================================================== */

static void
fpi_device_fte4800_init (FpiDeviceFte4800 *self)
{
  self->spi_fd = -1;
}

static void
fpi_device_fte4800_finalize (GObject *object)
{
  FpiDeviceFte4800 *self = FPI_DEVICE_FTE4800 (object);

  g_clear_pointer (&self->image_buf, g_free);
  G_OBJECT_CLASS (fpi_device_fte4800_parent_class)->finalize (object);
}

static void
fpi_device_fte4800_class_init (FpiDeviceFte4800Class *klass)
{
  FpDeviceClass      *dev_class = FP_DEVICE_CLASS (klass);
  FpImageDeviceClass *img_class = FP_IMAGE_DEVICE_CLASS (klass);

  dev_class->id        = "fte4800";
  dev_class->full_name = "FocalTech FTE4800 Fingerprint Sensor";
  dev_class->type      = FP_DEVICE_TYPE_UDEV;
  dev_class->id_table  = fte4800_id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = 5;

  img_class->img_width    = FTE4800_IMG_WIDTH;
  img_class->img_height   = FTE4800_IMG_HEIGHT;
  img_class->img_open     = fte4800_img_open;
  img_class->img_close    = fte4800_img_close;
  img_class->activate     = fte4800_activate;
  img_class->deactivate   = fte4800_deactivate;
  img_class->change_state = fte4800_change_state;

  G_OBJECT_CLASS (klass)->finalize = fpi_device_fte4800_finalize;
}
