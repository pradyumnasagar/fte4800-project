"""
FTE4800 trigger probe — fixed version.

Fixes:
- WAKEUP [0xFF,0x00,0x00,0x00] required at startup (exits deep-sleep, brings
  chip from stuck-0x0e to 0x02)
- Soft-reset chip at startup (was stuck in mode3 from previous run)
- FIFO read chunked into <=4096 byte pieces (Linux spidev limit)
- read16_fd removed (full-duplex confirmed not useful — chip broadcasts status)
- Use 2-phase TX+RX for all reads

fw9369_img_scan_start does:
  1. img_mode_init: mode9 → [mode0+mode10] → write16(0x1801) → write16(0x1800, 0x4FFE)
  2. mode3
  3. 10x fast poll for 0x54
  4. UNCONDITIONALLY: read16(0x1800), set bit0, write16(0x1800, 0x4FFF)
  5. sleep 1ms
  caller then: fifo_read(0x1A05, 10240)

Run as root: sudo python3 ~/spi_trigger.py
"""
import fcntl, struct, os, ctypes, time

SPI_IOC_WR_MODE32       = 0x40046b05
SPI_IOC_WR_MAX_SPEED_HZ = 0x40046b04

class xfer_t(ctypes.Structure):
    _fields_ = [
        ('tx_buf',           ctypes.c_uint64),
        ('rx_buf',           ctypes.c_uint64),
        ('len',              ctypes.c_uint32),
        ('speed_hz',         ctypes.c_uint32),
        ('delay_usecs',      ctypes.c_uint16),
        ('bits_per_word',    ctypes.c_uint8),
        ('cs_change',        ctypes.c_uint8),
        ('tx_nbits',         ctypes.c_uint8),
        ('rx_nbits',         ctypes.c_uint8),
        ('word_delay_usecs', ctypes.c_uint8),
        ('pad',              ctypes.c_uint8),
    ]

def SPI_IOC_MSG(n):
    return 0x40006b00 | ((n * 32) << 16)

# Increase spidev bufsiz before opening — kernel counts tx_total + rx_total
# across all transfers, so TX(6)+RX(N) costs 6+2N bytes against bufsiz.
# Default 4096 → max RX = 2045 bytes per call. Set to 65536 for full reads.
try:
    with open('/sys/module/spidev/parameters/bufsiz', 'w') as f:
        f.write('65536\n')
    print("spidev bufsiz set to 65536")
except Exception as e:
    print(f"Warning: could not set spidev bufsiz: {e} — will use small chunks")

fd = os.open('/dev/spidev0.0', os.O_RDWR)
fcntl.ioctl(fd, SPI_IOC_WR_MODE32,       struct.pack('I', 0))
fcntl.ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, struct.pack('I', 1_000_000))

def spi_tx(tx_bytes):
    n  = len(tx_bytes)
    tx = (ctypes.c_uint8 * n)(*tx_bytes)
    x  = xfer_t()
    x.tx_buf = ctypes.addressof(tx)
    x.len    = n
    fcntl.ioctl(fd, SPI_IOC_MSG(1), x)

def spi_tx_rx(tx_bytes, rx_len):
    """CS held: TX phase then RX phase."""
    n_tx = len(tx_bytes)
    tx   = (ctypes.c_uint8 * n_tx)(*tx_bytes)
    d_tx = (ctypes.c_uint8 * rx_len)(0)
    rx   = (ctypes.c_uint8 * rx_len)(0)
    xfers = (xfer_t * 2)()
    xfers[0].tx_buf = ctypes.addressof(tx)
    xfers[0].len    = n_tx
    xfers[1].tx_buf = ctypes.addressof(d_tx)
    xfers[1].rx_buf = ctypes.addressof(rx)
    xfers[1].len    = rx_len
    fcntl.ioctl(fd, SPI_IOC_MSG(2), xfers)
    return bytes(rx)

def read8(reg):
    return spi_tx_rx([0x08, 0xF7, reg & 0xFF, 0x00, 0x00], 1)[0]

def read16(addr):
    hi = ((addr >> 8) & 0xFF) | 0x80
    lo = addr & 0xFF
    rx = spi_tx_rx([0x04, 0xFB, hi, lo, 0x00, 0x01], 2)
    return (rx[0] << 8) | rx[1]

def write16(addr, val):
    hi = ((addr >> 8) & 0xFF) | 0x80
    lo = addr & 0xFF
    spi_tx([0x05, 0xFA, hi, lo, 0x00, 0x01, (val >> 8) & 0xFF, val & 0xFF])

def wakeup():
    """Required at session start — exits deep-sleep, brings chip to 0x02."""
    spi_tx([0xFF, 0x00, 0x00, 0x00])

def mode11_reset():
    """Mode 11 (soft reset) sends ONLY 1 byte (confirmed from DLL disasm)."""
    spi_tx([0x70])

def mode_cmd(cmd):
    spi_tx([cmd, (~cmd) & 0xFF, 0x00])

def write8(reg, val):
    """SPI0_Write8 (DLL VA 0x180018080): TX=[0x09,0xF6,reg,val] (4B, no RX)."""
    spi_tx([0x09, 0xF6, reg & 0xFF, val & 0xFF])

def init_regs(gain_param):
    """SPI_InitRegs (DLL VA 0x180017fe8): PLL calibration sequence.

    Sequence:
      write8(0xF1, gain_param)  — gain register
      write8(0xF4, 0xC0)        — PLL config
      write8(0xF4, 0xC1)        — PLL toggle (start PLL)
      write8(0xF4, 0xC0)        — PLL settle
      write8(0xF4, 0xC0)        — PLL settle
      read8(0xF3)               — calibration result (return value)
    """
    write8(0xF1, gain_param)
    write8(0xF4, 0xC0)
    write8(0xF4, 0xC1)
    write8(0xF4, 0xC0)
    write8(0xF4, 0xC0)
    return read8(0xF3)

def fifo_read_chunked(addr, total_len, chunk=512):
    """Read FIFO in chunks.

    CRITICAL: The chip's FIFO count field is n_WORDS (n_bytes/2), not n_bytes.
    From fw9369_fifo_read disassembly: count is shifted right by 1 (divided by 2)
    before encoding into buf[4,5].

    Also: spidev kernel limit is tx_total+rx_total <= bufsiz=4096.
    For TX(6)+RX(N): total = 6+2N <= 4096 → N <= 2045.
    Using chunk=512 for safety.
    """
    result = bytearray()
    remaining = total_len
    hi = ((addr >> 8) & 0xFF) | 0x80
    lo = addr & 0xFF
    while remaining > 0:
        n = min(remaining, chunk)
        nwords = n // 2  # FIFO count is in 16-bit words
        data = spi_tx_rx([0x06, 0xF9, hi, lo, (nwords >> 8) & 0xFF, nwords & 0xFF], n)
        result.extend(data)
        remaining -= n
    return bytes(result)

print("=" * 64)
print("FTE4800 trigger probe v4 — correct DLL init order (pre_hw_init → hw_init)")
print("=" * 64)

# ─── ALWAYS: wakeup → mode11(1B) → mode0 → wakeup → expect 0x02 ──────────────
print("\n[RESET] Wakeup + soft reset...")
wakeup()
time.sleep(0.020)
mode11_reset()   # mode 11: 1 byte [0x70] — soft reset
time.sleep(0.100)
mode_cmd(0xC0)   # mode 0: idle
time.sleep(0.050)
wakeup()         # second wakeup needed to reach 0x02
time.sleep(0.020)
s = read8(0x80)
print(f"  Status after reset: reg8[0x80] = 0x{s:02x}  (want 0x02)")

# ─── pre_hw_init: init_func_1 (mode9→mode10) — BEFORE PLL calibration! ───────
# DLL: pre_hw_init(ecx=0) at VA 0x18000fa90 → calls init_func_1 (mode9→mode10)
# at VA 0x180010ce8, THEN fw9369_hw_init (PLL) is called.
# In our previous probes, init_func was AFTER PLL — that was WRONG.
print("\n[PRE-INIT] init_func_1 (mode9→mode10) — BEFORE PLL init (from pre_hw_init):")
mode_cmd(0x5A)   # mode 9: FDT finger-down
time.sleep(0.005)
s = read8(0x80)
print(f"  After mode9: reg8[0x80] = 0x{s:02x}  (expect 0x50 for finger-up-ready)")
if s != 0x50:
    mode_cmd(0xC0)   # mode 0 first if not 0x50 (from init_func_1 logic)
    time.sleep(0.003)
mode_cmd(0xA5)   # mode 10: FDT finger-up (always done last in init_func_1)
time.sleep(0.010)
s = read8(0x80)
print(f"  After mode10: reg8[0x80] = 0x{s:02x}  (want 0x50)")

# ─── fw9369_hw_init: SPI_InitRegs PLL calibration ─────────────────────────────
# DLL calls fw9369_hw_init (VA 0x180010900) AFTER pre_hw_init.
# While chip is in FDT UP mode (mode10), run the PLL calibration.
print("\n[HW-INIT] fw9369_hw_init — PLL calibration (chip is now in mode10/FDT-up):")
cal1 = init_regs(0x03)   # SPI_InitRegs(0x03): gain + PLL sequence
print(f"  init_regs(0x03): cal1=0x{cal1:02x}")
cal2 = init_regs(0x13)   # SPI_InitRegs(0x13): gain + PLL sequence
print(f"  init_regs(0x13): cal2=0x{cal2:02x}")
time.sleep(0.005)         # brief settle after PLL init

# ─── chip version check (post_hw_init_1 at 0x180010b6c, loops ×10) ────────────
print("\n[VER-CHECK] Chip version register 0x9B (loops up to 10x in DLL):")
for attempt in range(10):
    chip_ver = read8(0x9B)
    ver_nibble = chip_ver >> 2
    print(f"  attempt {attempt}: reg8[0x9B] = 0x{chip_ver:02x}  (>>2 = 0x{ver_nibble:02x}, want 0x13)")
    if ver_nibble == 0x13:
        print(f"  ✓ FT9369 silicon confirmed!")
        break
    time.sleep(0.005)

# ─── Chip ID (fixed register) ─────────────────────────────────────────────────
chip_id = read16(0x85C0)
print(f"\n  chip_id reg16[0x85C0] = 0x{chip_id:04x}  (want 0x9369)")

# ─── Startup FIFO config (write16(0x1A84, 0xFFFF)) ───────────────────────────
write16(0x1A84, 0xFFFF)
print(f"  write16(0x1A84, 0xFFFF)  — from DLL startup chain")

# ─── Baseline ─────────────────────────────────────────────────────────────────
print("\n[0] Baseline after full init:")
print(f"  reg8[0x80]   = 0x{read8(0x80):02x}")
v1800 = read16(0x1800)
v1801 = read16(0x1801)
print(f"  reg16[0x1800] = 0x{v1800:04x}")
print(f"  reg16[0x1801] = 0x{v1801:04x}")

# ─── init_func_0 (prepare for scan) ──────────────────────────────────────────
print("\n[1] init_func_0 (prepare FDT for scan, same as DLL img_mode_init):")
mode_cmd(0x5A)   # mode 9
time.sleep(0.005)
s = read8(0x80)
print(f"  After mode9: reg8[0x80] = 0x{s:02x}  (expect 0x50)")
if s != 0x50:
    mode_cmd(0xC0)
    time.sleep(0.003)
    mode_cmd(0xA5)   # mode 10
    time.sleep(0.003)
    s2 = read8(0x80)
    print(f"  After mode0+mode10: reg8[0x80] = 0x{s2:02x}")

# ─── Config writes ────────────────────────────────────────────────────────────
print("\n[2] Config writes:")
FDT_VAL = 0xFC80   # best-effort: compute_func(0xFC80, 6, 0, 0)
write16(0x1801, FDT_VAL)
write16(0x1800, 0x4FFE)
time.sleep(0.001)
v1800_after = read16(0x1800)
print(f"  write16(0x1801, 0x{FDT_VAL:04x})  write16(0x1800, 0x4FFE)")
print(f"  Readback 0x1800 = 0x{v1800_after:04x}")
# Note: byte[0] is pipeline state, byte[1] should be 0xFE if write worked
print(f"  Write16 working? byte[1]=0x{v1800_after & 0xFF:02x} (expect 0xFE if yes, was 0xEF if no)")

# ─── Full scan sequence ───────────────────────────────────────────────────────
print("\n[3] Full scan sequence:")
print("  PLACE FINGER ON SENSOR, press Enter")
input("  >>> ")

# Re-run init_func_0 with finger present
mode_cmd(0x5A)
time.sleep(0.003)
s = read8(0x80)
print(f"  Status after mode9 (with finger): 0x{s:02x}")
if s != 0x50:
    mode_cmd(0xC0)
    time.sleep(0.002)
    mode_cmd(0xA5)
    time.sleep(0.002)

write16(0x1801, FDT_VAL)
write16(0x1800, 0x4FFE)

# mode3 scan
print("  → mode3")
mode_cmd(0xC4)

# 20 fast polls
found_54 = False
for i in range(20):
    v = read8(0x80)
    if v == 0x54:
        print(f"  *** 0x54 at poll {i} ***")
        found_54 = True
        break

print(f"  After 20 polls: last status = 0x{v:02x}  {'(image ready!)' if found_54 else ''}")

# Unconditional trigger: write 0x4FFF to 0x1800
print("  → trigger: write16(0x1800, 0x4FFF)")
write16(0x1800, 0x4FFF)
time.sleep(0.002)   # 1-2ms

# ─── FIFO read ────────────────────────────────────────────────────────────────
def try_read_fifo(label, delay_s):
    print(f"\n[FIFO] {label}:")
    time.sleep(delay_s)
    img = fifo_read_chunked(0x1A05, 10240)
    nz = sum(1 for b in img if b != 0)
    mn, mx = min(img), max(img)
    import statistics
    try:
        std = statistics.stdev(img)
    except Exception:
        std = 0
    print(f"  Non-zero: {nz}/10240 ({nz/102.4:.1f}%)")
    print(f"  Range: {mn}..{mx},  stdev={std:.1f}")
    print(f"  First 32: {img[:32].hex(' ')}")
    if nz > 500 and std > 5:
        fn = f'/tmp/fte4800_{label.replace(" ","_")}.pgm'
        with open(fn, 'wb') as f:
            f.write(b'P5\n80 128\n255\n')
            f.write(img)
        print(f"  Saved: {fn}  (view: eog {fn})")
    return img, nz

img1, nz1 = try_read_fifo("immediate", 0)

# ─── Retry with longer delays ─────────────────────────────────────────────────
print("\n[4] Retry with 50ms delay:")
print("  KEEP FINGER, press Enter")
input("  >>> ")
mode_cmd(0x5A)
time.sleep(0.003)
write16(0x1801, FDT_VAL)
write16(0x1800, 0x4FFE)
mode_cmd(0xC4)
print(f"  Waiting 50ms... status={read8(0x80):02x}")
time.sleep(0.050)
print(f"  Status after 50ms: 0x{read8(0x80):02x}")
write16(0x1800, 0x4FFF)
img2, nz2 = try_read_fifo("50ms", 0.002)

print("\n[5] Retry with 500ms delay:")
print("  KEEP FINGER, press Enter")
input("  >>> ")
mode_cmd(0x5A)
time.sleep(0.003)
write16(0x1801, FDT_VAL)
write16(0x1800, 0x4FFE)
mode_cmd(0xC4)
print("  Waiting 500ms...")
time.sleep(0.500)
print(f"  Status after 500ms: 0x{read8(0x80):02x}")
write16(0x1800, 0x4FFF)
img3, nz3 = try_read_fifo("500ms", 0.002)

# ─── Try WITHOUT the 0x1800 trigger (just mode3 + wait + raw FIFO) ─────────────
print("\n[6] Try: mode3 + wait + FIFO WITHOUT trigger write:")
print("  KEEP FINGER, press Enter")
input("  >>> ")
mode_cmd(0x5A)
time.sleep(0.003)
write16(0x1801, FDT_VAL)
write16(0x1800, 0x4FFE)
mode_cmd(0xC4)
time.sleep(0.200)
s_200 = read8(0x80)
print(f"  Status after 200ms: 0x{s_200:02x}")
# NO trigger write
img4, nz4 = try_read_fifo("notrigger_200ms", 0)

# ─── Best result summary ──────────────────────────────────────────────────────
print("\n[SUMMARY]")
print(f"  immediate:      {nz1}/10240 non-zero ({nz1/102.4:.1f}%)")
print(f"  50ms:           {nz2}/10240 non-zero ({nz2/102.4:.1f}%)")
print(f"  500ms:          {nz3}/10240 non-zero ({nz3/102.4:.1f}%)")
print(f"  no-trigger200ms:{nz4}/10240 non-zero ({nz4/102.4:.1f}%)")
best_nz = max(nz1, nz2, nz3, nz4)
print(f"  Best: {best_nz} non-zero bytes")

os.close(fd)
print("\nDone.")
