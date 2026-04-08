# FTE4800 Fingerprint Sensor Driver

Linux libfprint driver for the FocalTech FTE4800 fingerprint sensor.

## Sensor Information

- **Sensor**: FocalTech FTE4800 (silicon FT9369)
- **Bus**: SPI (ACPI path `_SB.PC00.SPI2.FPNT`, ACPI ID "FTE4800")
- **Host**: CHUWI ZeroBook 13 / Fedora 43
- **Image Size**: 10240 bytes (80x128 pixels)

## Project Status

**Working:**
- SPI protocol fully reverse-engineered from Windows DLL
- Kernel module for GPIO power/reset control (fte4800_pwr.ko)
- Basic device communication and init sequence
- Capture state machine implemented

**Not Working (Known Issues):**
- Image capture returns status echo instead of actual image data
- "0x54" (image ready) status never achieved
- Minutiae detection fails (no valid image data)

## Hardware Setup

```
GPIO535 → AVDD (power enable)
GPIO357 → RESET (hardware reset)
SPI bus: /dev/spidev0.0
```

## Build & Test

### 1. Load Kernel Module
```bash
cd fte4800-project
sudo rmmod fte4800_pwr 2>/dev/null
sudo insmod fte4800_pwr.ko
```

### 2. Build libfprint Driver
```bash
# Copy driver files to libfprint
cp fte4800.c fte4800.h ~/libfprint/libfprint/drivers/fte4800/

# Build
cd ~/libfprint
ninja -C build
sudo ninja -C build install
sudo systemctl restart fprintd
```

### 3. Test Enrollment
```bash
fprintd-enroll
```

### 4. Debug Output
```bash
journalctl -u fprintd -f
G_MESSAGES_DEBUG=all fprintd-enroll 2>&1
```

## Key Files

| File | Description |
|------|-------------|
| `fte4800.c` | Main libfprint driver |
| `fte4800.h` | Driver header with constants |
| `fte4800_pwr.c` | Kernel module source for GPIO control |
| `fte4800_pwr.ko` | Compiled kernel module |
| `spi_trigger.py` | Python SPI probe script |
| `ftWbioUmdfDriverV2.dll` | Windows driver (reverse-engineering source) |

## SPI Protocol Summary

| Command | TX | RX |
|---------|----|----|
| Wakeup | `[0xFF,0,0,0]` | - |
| Mode | `[cmd,~cmd,0x00]` | - |
| Read8 | `[0x08,0xF7,reg,0,0]` | 1B |
| Write8 | `[0x09,0xF6,reg,val]` | - |
| Read16 | `[0x04,0xFB,hi\|80,lo,0,1]` | 2B BE |
| Write16 | `[0x05,0xFA,hi\|80,lo,0,1,vh,vl]` | - |
| FIFO | `[0x06,0xF9,hi\|80,lo,cnt_hi,cnt_lo]` | N bytes |

## Key Registers

| Register | Address | Description |
|----------|---------|-------------|
| STATUS | 0x80 | 0x02=idle, 0x50=FDT-up, 0x54=image-ready, 0xCE=finger |
| CHIP_ID | 0x85C0 | Returns 0x9369 (FT9369) |
| FDT_CFG | 0x1801 | FDT configuration (0xFCB9) |
| SCAN_CFG | 0x1800 | 0x4FFE=arm, 0x4FFF=trigger |
| FIFO | 0x1A05 | Image FIFO (10240 bytes) |

## Known Issues

1. **FIFO returns 0xEF status echo** - Image data never captured properly
2. **0x54 status never achieved** - Image ready status never appears
3. **Garbage image data** - Even when read succeeds, returns status echo

## References

- libfprint project: https://gitlab.freedesktop.org/3v1n0/libfprint
- Windows driver: `ftWbioUmdfDriverV2.dll` (v2.2.3.79)