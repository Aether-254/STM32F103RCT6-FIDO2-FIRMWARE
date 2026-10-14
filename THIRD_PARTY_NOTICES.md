# Third-party notices and scope of the project license

The root MIT LICENSE covers original project contributions, not an automatic
relicensing of dependencies or generated/vendor source. Preserve their copyright
headers and applicable licenses when redistributing source or firmware.

| Component | Location | Notice / license |
| --- | --- | --- |
| ST STM32F1 HAL | `Drivers/STM32F1xx_HAL_Driver` | BSD-3-Clause as stated in source; reproduced in `licenses/ST-HAL-BSD-3-Clause.txt` |
| ARM CMSIS | `Drivers/CMSIS` | See `Drivers/CMSIS/LICENSE.txt` and individual headers |
| ST device headers, startup / generated integration | `Drivers/CMSIS/Device`, `Core`, `USB_DEVICE`, startup assembly | Retain individual ST notices; project MIT does not remove upstream conditions |
| ST USB Device Library | `Middlewares/ST/STM32_USB_Device_Library` | Source headers reference ST SLA0044; full ST-published terms supplied in `licenses/ST-USB-SLA0044.md` |
| Mbed TLS 3.6.7 | `third_party/mbedtls-3.6.7` | See its `LICENSE`, per-file SPDX identifiers and `SOURCE.json` hash manifest |

ST USB middleware is not described as MIT-licensed. The supplied SLA0044 text
is the ST-published version retrieved on 2026-10-14; no claim is made that it
retroactively changes the original package terms. Its ST-device restrictions
and other conditions require review before reuse outside this STM32 project.

Original sources for the supplied ST license texts:
- https://github.com/STMicroelectronics/stm32f1xx-hal-driver/blob/master/LICENSE.md
- https://github.com/STMicroelectronics/stm32-mw-usb-device/blob/master/LICENSE.md

CanoKey is research-only and not linked into this firmware. The local reference
checkout is deliberately excluded from this repository; upstream source is
https://github.com/canokeys/canokey-stm32 . Research notes remain local.
Likewise local downloaded board reference files are excluded pending a complete
redistribution-license audit; public provenance URLs remain in the documentation.

Host development tools are installed via `uv.lock`, not vendored executables.
Flash backups, real credential data, review comments and local diagnostic captures
are not public source artifacts and must not be committed.
