# Firmware list
- dpm.dm
- dpm.pm
- mcupm.bin
- spm_firmware.bin
- sspm.bin

--------------------------------------------------------------------------------
# DPM introduction
DPM is a hardware module for DRAM Power Management, which is used for DRAM low power.
For example: self refresh, disable PLL/DLL when not in use.

DPM includes two parts of images: data part (`dpm.dm`) and program part (`dpm.pm`).

## Who uses it
Coreboot loads dpm at ramstage, and copies `dpm.dm` & `dpm.pm` to DPM SRAM.

## How to load DPM
Use CBFS to load `dpm.dm` and `dpm.pm`.
No need to pass other parameters to DPM.

## Return values
No return value.

## Add version
```
$ echo -n 'DPMD Firmware version: x.x' >> dpm.dm
$ echo -n 'DPMP Firmware version: x.x' >> dpm.pm
```

## Version
```
$ strings dpm.dm | grep version
$ strings dpm.pm | grep version
```

--------------------------------------------------------------------------------
# MCUPM introduction
MCUPM is a hardware module which is used for MCUSYS Power Management.
MCUPM firmware (`mcupm.bin`) is loaded into MCUPM SRAM at system initialization.

## Who uses it
Coreboot will load MCUPM at ramstage. It will copy mcupm.bin to MCUPM SRAM.

## How to load `mcupm.bin`
Use CBFS to load `mcupm.bin`, then set normal boot flag and release software reset pin of MCUPM.

## Return values
No return value.

## Version
`$ strings mcupm.bin | grep "MCUPM firmware"`

--------------------------------------------------------------------------------
# SPM introduction
SPM is "System Power Manager" that provides power control for low power task.
SPM provides power related features, e.g. Suspend, Vcore dvfs

SPM firmware is loaded into SPM SRAM at system initialization.

## Who uses it
Coreboot will load spm_firmware.bin to SPM SRAM at ramstage.

## How to load `spm_firmware.bin
Use CBFS to load `spm_firmware.bin`.
No need to pass other parameters to SPM.

## Return value
No return value.

## Version
`$ strings spm_firmware.bin | grep "SPM firmware"`

--------------------------------------------------------------------------------
# SSPM introduction
SSPM is "Secure System Power Manager" that provides power control in secure domain.
SSPM provides power related features, e.g. CPU DVFS, thermal control, to offload
application processor for security reason.

SSPM firmware is loaded into SSPM SRAM at system initialization.

## Who uses it
Coreboot will load sspm.bin to SSPM SRAM at ramstage.

## How to load `sspm.bin`
Use CBFS to load `sspm.bin`.
No need to pass other parameters to SSPM.

## Return value
No return value.

## Version
`$ strings sspm.bin | grep "SSPM firmware"`
