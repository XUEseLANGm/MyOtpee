# AArch64 Architecture Support

SCP-firmware has limited support for the AArch64 architecture, specifically a
subset required to boot on Armv8-R64 machines, with the potential to extend to
Armv8-A machines in the future.

The AArch64 architecutre support follows the structure and interfaces defined on
the [Architechture Support](architecture_support.md) page.

Only the Armv8-R64 PMSA is currently supported. An initial memory map is
installed in arch_crt0.S, based on the firmware layout, which should be
customized using the armv8r_mpu module configuration.

Note that AArch64 support only uses one exception level, the initial EL at boot.
For Armv8-R64, this means the firmware runs exclusively at secure EL2, and no
attempts are made to initialize the EL1/0 environment.

Both GCC and Clang are supported, but not Arm Clang.

## Interrupt handling

A minimal interrupt controller is provided with the following limitations:

 * All interrupts have the same priority.
 * NMIs (non-maskable interrupts) are not supported.
 * The extended SPI and PPI ranges are not supported.

AArch64 products must provide a `fmw_gic.h` header which defines:

 * `GICD_BASE` - the base address of the GIC distributor
 * `GICR_BASE` - the base address of the GIC redstributor corresponding to the
   core on which SCP-firmware is running

## Usage

To use the AArch64 architecture in a product, including the following in
Firmware.cmake:

    set(SCP_ARCHITECTURE "aarch64")

The fvp-baser-aemv8r product can be used as a reference for implementing an
AArch64 product.
