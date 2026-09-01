# Star Labs secure-mode EC 26.09 release

- Version: 1a.08, secure-build ABI version 01
- Release date: 2026-09-01
- Controller silicon: ITE IT5570
- Source: Merlin commit `f3b0e9ddbecdbc06fc2accebb55cdfbfe05bf92b`
- Toolchain: SDCC 4.4.0; GNU objcopy 2.46

## Licence and corresponding source

The `ec-secure.bin` images are licensed under the
[GNU General Public License version 2 only](GPL-2.0-only.txt). The complete
corresponding source is Merlin commit
`f3b0e9ddbecdbc06fc2accebb55cdfbfe05bf92b`, including its build system and
the four configurations listed below. That commit must remain published and
available for as long as these binaries are distributed.

## Supported systems and files

| System | Merlin configuration | Binary | SHA-256 |
| --- | --- | --- | --- |
| StarBook Horizon | `config.starlabs_adl_horizon_secure` | `adl/hz/ec-secure.bin` | `c26fb84dc1858b14873986e822641f9c34655b1939dc542757b2b8f124074e3e` |
| StarBook Mk VIII | `config.starlabs_starbook_rpl_u_secure` | `starbook/rpl_u/ec-secure.bin` | `76eb05e6534c32bd67d1f4a472bfe079a3b4f46fa8fe2a5a32f8acdb22c7ff0f` |
| StarBook Mk VII | `config.starlabs_starbook_mtl_secure` | `starbook/mtl/ec-secure.bin` | `f89741e60de46db2a27f3c42482c7fe01e34ecd475d0960bc67ed3a29afad66b` |
| StarFighter Mk II | `config.starlabs_starfighter_mtl_secure` | `starfighter/mtl/ec-secure.bin` | `e4cda9c670e02cb8169cd3a705dc3ff1a3b9234cf8b2a01cb8b8fe709b75d0ab` |

Paths in the table are relative to `mainboard/starlabs/`.

## Requirements and dependencies

These images must be used with coreboot firmware which challenges and verifies
the secure-build ABI before restoring EC options. The source commit includes,
in order, the 26.09 I2EC read-only change, predefined SMBus flash-command
disable, host flash-gate clearing, legacy host flash-service isolation, and the
secure-mode policy.

Secure mode fixes adapter automatic-start off and permits departure from S5
hold only for an explicit boot request. The host flash service is not compiled
into these images.

## Published host ABI

The values below are read through the standard ACPI EC address space:

| Offset | Length | Meaning |
| --- | --- | --- |
| `0x00` | 1 byte | Firmware major version (`0x1a`) |
| `0x01` | 1 byte | Firmware minor version (`0x08`) |
| `0x02` | 1 byte | Secure-build signature (`0xa5`) |
| `0x03` | 1 byte | Secure-build ABI version (`0x01`) |
| `0x41` | 9 bytes | NUL-terminated build time, `HH/MM/SS` |
| `0x4b` | 11 bytes | NUL-terminated build date, `YYYY/MM/DD` |

Offsets `0x02` and `0x03` are virtual, read-only values. A host write must not
alter them. A consumer must challenge both offsets by writing values other than
the expected signature/version and then read back exactly `0xa5, 0x01`. Merely
reading those values is insufficient because older EC firmware exposed the
same RAM locations as writable storage.

## Changes from the normal 1a.08 images

- Removes the unauthenticated legacy host flash service.
- Makes the secure-build identity immutable to host writes.
- Makes I2EC flash access read-only.
- Disables predefined SMBus flash commands.
- Clears host flash-write gates during controller startup.
- Disables persisted adapter automatic-start policy.

## Errata and known issues

- Hardware validation of the complete coreboot, EC, EDK II, TPM, and physical
  boot-key chain is pending.
- Build date and time are embedded in each binary; rebuilds are not
  byte-for-byte reproducible unless those inputs are fixed.
- These images are not interchangeable with normal `ec.bin` images. Coreboot
  must select `ec-secure.bin` only for the enhanced-security profile.
