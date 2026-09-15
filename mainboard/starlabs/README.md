This project has mixed licencing. You are free to copy, redistribute and/or modify aspects of this work under the terms of each licence accordingly (unless otherwise specified).

Graphical assets (any and all source `.svg` files or rendered `.png` or `.bmp` files) are licensed under the terms of the [Creative Commons Attribution-ShareAlike 4.0 License](https://creativecommons.org/licenses/by-sa/4.0/).

Any and all `ec.bin` files are licensed under the terms of the [MIT License](MIT.md). This applies only to the firmware binary. The source code is proprietary and not available for customer use.

## Merlin 26.10 EC images

Built on 2026-10-07 from Merlin commit
`cc714fb099149356d31c0049cd07c441237faa94` with SDCC 4.4.0 #14620.
The source includes PR #809 and a separate version bump to 26.10.

Changes from the previous 26.09 images:

- Leave the Horizon kill-switch input unbiased during normal operation.
- Enable wireless after the Wi-Fi and Bluetooth power-sequence entries.
- Pull the kill-switch input down in S5/G3 and release it during power-up.

Use the EC image matching the mainboard; these images are not interchangeable.
They retain the existing host interface and 128 KiB image format. All 14 board
builds completed; hardware qualification of this exact build is pending.

| Board configuration | EC | Image |
|---|---|---|
| `byte_cezanne` | IT5570 | [cezanne/byte/ec.bin](cezanne/byte/ec.bin) |
| `byte_adl` | IT5570 | [adl/y2/ec.bin](adl/y2/ec.bin) |
| `lite_adl` | IT5570 | [adl/i5/ec.bin](adl/i5/ec.bin) |
| `starbook_cezanne` | IT5570 | [cezanne/starbook/ec.bin](cezanne/starbook/ec.bin) |
| `labtop_cml` | IT8987 | [starbook/cml/ec.bin](starbook/cml/ec.bin) |
| `starbook_adl` | IT5570 | [starbook/adl/ec.bin](starbook/adl/ec.bin) |
| `starbook_tgl` | IT5570 | [starbook/tgl/ec.bin](starbook/tgl/ec.bin) |
| `starbook_rpl` | IT5570 | [starbook/rpl/ec.bin](starbook/rpl/ec.bin) |
| `starbook_mtl` | IT5570 | [starbook/mtl/ec.bin](starbook/mtl/ec.bin) |
| `starbook_adl_n` | IT5570 | [starbook/adl_n/ec.bin](starbook/adl_n/ec.bin) |
| `starfighter_rpl` | IT5570 | [starfighter/rpl/ec.bin](starfighter/rpl/ec.bin) |
| `starfighter_mtl` | IT5570 | [starfighter/mtl/ec.bin](starfighter/mtl/ec.bin) |
| `adl_horizon` | IT5570 | [adl/hz/ec.bin](adl/hz/ec.bin) |
| `starbook_rpl_u` | IT5570 | [starbook/rpl_u/ec.bin](starbook/rpl_u/ec.bin) |

### EC version interface

ABI version: not separately versioned. The version fields are unchanged:
read bytes 0x00 and 0x01 through the ACPI EC address space as unsigned integers
for the major and minor version. These images report 0x1a and 0x0a (26.10).
`merlin-console` displays both the version and the build date/time.
The complete source-level ABI is not publicly documented.

### StarFighter Phoenix

The [Phoenix EC image](phoenix/starfighter/ec.bin) is built from Merlin
`6d407f9bcf0d114d05eb6358961fdab2b7e37b37` on `26.10_amd` with
SDCC 4.4.0 #14620. It uses the same 128 KiB format and reports 26.09.
Hardware qualification of this exact build is pending.
