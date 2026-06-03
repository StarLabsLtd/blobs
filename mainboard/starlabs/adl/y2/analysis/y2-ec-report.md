# Y2 EC Reverse-Engineering Notes

## Summary

`ec.bin` is a raw 128 KiB ITE embedded-controller firmware image for an old
Keil/8051-based EC codebase. It is not compressed or encrypted. It is practical
to reverse engineer this image with source assistance from the reference EC
trees under:

`/home/sean/Insync/sean@starlabs.systems/Google Drive - Shared drives/Development/Reference Code/ECs`

The closest donor family in the available archives is `b5`, with the best ROM
match being `b5/ROM/IN1_EC_V01.00.bin` at `69.85%` byte identity.

## Local Artifacts

- Inspection dump: [ec.inspection.txt](/home/sean/Documents/blobs/mainboard/starlabs/adl/y2/analysis/ec.inspection.txt)
- Donor similarity ranking: [ec.reference-similarity.tsv](/home/sean/Documents/blobs/mainboard/starlabs/adl/y2/analysis/ec.reference-similarity.tsv)
- Best-donor chunk map: [ec.best-donor-chunks.tsv](/home/sean/Documents/blobs/mainboard/starlabs/adl/y2/analysis/ec.best-donor-chunks.tsv)
- Helper script: [ec_re_assist.sh](/home/sean/Documents/blobs/mainboard/starlabs/adl/y2/tools/ec_re_assist.sh)

## Firm Identifiers

The image contains clear build metadata in the same layout used by the
reference EC source trees:

- Offset `0x0050`: `ITE EC-V14.6   `
- Offset `0x7f80`: `INTEL ICL MRD.$`
- Offset `0x7f90`: `2025/10/28`
- Offset `0x7f9b`: `13:43:02`
- Offset `0x7fa4`: `EC-DNB19-1.09-BOSGAME-TEST`

The build string layout matches [OEM_VER.C](/home/sean/Insync/sean@starlabs.systems/Google%20Drive%20-%20Shared%20drives/Development/Reference%20Code/ECs/b5/Code/OEM/OEM/OEM_BANK0/OEM_VER.C:17), where `SIGN_MUFG`, `SIGN_DATE`, `SIGN_TIME`, and `SIGN_ECVR` are emitted into the binary.

## Structural Matches

The first bytes decode cleanly as 8051 reset and interrupt vectors:

```text
ljmp 0x0070
ljmp 0x0ba5
mov 0x36, #0x02
ret
ret
ljmp 0x0ba6
...
```

That lines up with the reference ITE/Keil 8051 environment, including the SFR
model in [CORE_CHIPSFR.H](/home/sean/Insync/sean@starlabs.systems/Google%20Drive%20-%20Shared%20drives/Development/Reference%20Code/ECs/b5/Code/CHIP/INCLUDE/CORE_CHIPSFR.H:17).

Using the standard 8051 vector layout, the first `0x40` bytes give this
inferred entry map:

- `0x0000`: reset vector -> `0x0070`
- `0x0003`: external interrupt 0 -> `0x0ba5`
- `0x000b`: timer 0 -> `0x0ba6`
- `0x0013`: external interrupt 1 -> `0x0bd3`
- `0x001b`: timer 1 -> `0x0c1f`
- `0x0023`: serial -> `0x0c4f`
- `0x002b`: timer 2 -> `0x0c50`
- `0x003d`: extra vendor-specific jump -> `0x2887`

The signature block at offset `0x40` also matches the ITE chip-identification
table in [CORE_ITEString.C](/home/sean/Insync/sean@starlabs.systems/Google%20Drive%20-%20Shared%20drives/Development/Reference%20Code/ECs/b5/Code/CHIP/CORE_ITEString.C:39). The bytes in `ec.bin` correspond to the IT557x eSPI mirror variant, which is consistent with the reference trees used for Intel ICL-era boards.

## Donor Lineage

The strongest donor signal is from the `b5` ROM set:

- `69.85%` identical: `b5/ROM/IN1_EC_V01.00.bin`
- `69.10%` identical: `b5/ROM/TN1_EC_V0.05_20200628A/TN1_EC_V0.05.bin`
- `69.02%` identical: `b5/ROM/TN1_EC_V0.07_20200901B/TN1_EC_V0.07.bin`
- `65.31%` identical: `b62/ROM/DN1E_EC_V1.00_140M5_YD_StarLabs_20230627A/DN1E_EC_V1.00.bin`

The local sibling ADL blobs are materially farther away:

- `54.88%` identical: `../hz/ec.bin`
- `54.80%` identical: `../i5/ec.bin`

That suggests `y2/ec.bin` is not just a trivial rebrand of the other local ADL
blobs. It is closer to an older `b5`-line OEM codebase than to those sibling
images.

## Confidence Markers

- The donor binaries and `ec.bin` place `ITE EC-V14.6` at offset `0x50`.
- The donor binaries and `ec.bin` place `INTEL ICL MRD.$` at offset `0x7f80`.
- The best donor (`IN1_EC_V01.00.bin`) shares one long identical run of `31796`
  bytes starting at offset `0x183cc`.

That is enough shared structure to use donor ROMs and donor source as a map for
substantial parts of the binary, even though the exact `DNB19/BOSGAME` OEM
source is not present in the available source archive.

The chunk map against `IN1_EC_V01.00.bin` is stronger than the overall `69.85%`
figure suggests. Several 4 KiB regions are `100%` identical, especially from
`0x11000` through `0x17000` and from `0x19000` through `0x1f000`. That usually
means large stretches of common kernel or lightly customized OEM code can be
borrowed directly for naming and control-flow recovery.

## Working Assumption

Use `b5` as the primary donor tree for naming and code-shape recovery. Use
`b62` as a secondary reference because it is StarLabs-adjacent and still shares
the same ITE kernel layout, signatures, and build conventions.

## Practical Next Targets

These are the next useful RE passes, in order:

1. Map the reset and interrupt vector targets at the top of bank 0.
2. Identify the OEM build/version handling around the `0x7f80` metadata block.
3. Diff the best donor ROM against `y2/ec.bin` by region to isolate board-
   specific OEM changes.
4. Use `b5/Code/OEM/OEM_BANK*` as the first naming pass for keyboard, GPIO, fan,
   ACPI, battery, and power-sequencing routines.
5. Build an annotated symbol map rather than aiming for literal C decompilation.

## Limits

This workflow can recover function boundaries, data tables, subsystem behavior,
and likely source-file provenance. It will not recover the original
`DNB19/BOSGAME` C sources verbatim unless that exact OEM tree exists somewhere
else.
