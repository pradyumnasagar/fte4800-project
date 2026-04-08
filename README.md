# FTE4800 Fingerprint Sensor Driver

Linux libfprint driver for the FocalTech FTE4800 fingerprint sensor.

## Sensor Information

- **Sensor**: FocalTech FTE4800 (silicon FT9369)
- **Bus**: SPI (ACPI path `_SB.PC00.SPI2.FPNT`, ACPI ID "FTE4800")
- **Host**: CHUWI ZeroBook 13 / Fedora 43
- **Image Size**: 10240 bytes (80x128 pixels)

## Project Status

**Working:**
- SPI protocol fully reverse-engineered
- Kernel module for GPIO power/reset control
- Basic device communication
- libfprint driver skeleton

**Not Working:**
- Image capture (0x54 status never achieved)
- Driver hanging during enrollment

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
| `fte4800_pwr.c` | Kernel module for GPIO control |
| `spi_trigger.py` | Python probe script |
| `FTE4800_HANDOFF.md` | Detailed handoff notes |

## SPI Protocol Summary

| Command | TX | RX |
|---------|----|----|
| Wakeup | `[0xFF,0,0,0]` | - |
| Read8 | `[0x08,0xF7,reg,0,0]` | 1B |
| Read16 | `[0x04,0xFB,hi\|80,lo,0,1]` | 2B |
| Write16 | `[0x05,0xFA,hi\|80,lo,0,1,vh,vl]` | - |
| FIFO | `[0x06,0xF9,hi\|80,lo,cnt_hi,cnt_lo]` | N bytes |

## Known Issues

1. **0x54 status never achieved** - Image ready status never appears
2. **Driver hangs** - Init or capture SSM blocking
3. **FIFO read returns garbage** - Count must be in WORDS (not bytes)

## References

- libfprint project: https://gitlab.freedesktop.org/3v1n0/libfprint
- Windows driver: `ftWbioUmdfDriverV2.dll` (v2.2.3.79)