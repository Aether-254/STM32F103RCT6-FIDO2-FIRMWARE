cmake_minimum_required(VERSION 3.22)

#
# This file is generated only once,
# and is not re-generated if converter is called multiple times.
#
# User is free to modify the file as much as necessary
#

# Setup compiler settings
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)


# Define the build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug")
endif()

# Set the project name
set(CMAKE_PROJECT_NAME fido2-key)

# Enable compile command to ease indexing with e.g. clangd
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

# Core project settings
project(${CMAKE_PROJECT_NAME})
message("Build type: " ${CMAKE_BUILD_TYPE})

# Enable CMake support for ASM and C languages
enable_language(C ASM)

# Create an executable object type
add_executable(${CMAKE_PROJECT_NAME})
option(KEY_SD_READONLY_DIAGNOSTIC "Read-only SPI SD startup diagnostic (no card writes)" OFF)
option(KEY_OTP_SELFTEST "Public RFC OTP startup self-test (no real secrets/storage writes)" OFF)
if(KEY_OTP_SELFTEST)
    target_sources(${CMAKE_PROJECT_NAME} PRIVATE Core/Src/key_otp_selftest.c)
    target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE KEY_OTP_SELFTEST)
endif()
if(KEY_SD_READONLY_DIAGNOSTIC)
    target_sources(${CMAKE_PROJECT_NAME} PRIVATE Core/Src/board_sd.c)
    target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE KEY_SD_READONLY_DIAGNOSTIC)
endif()
set_property(TARGET ${CMAKE_PROJECT_NAME} APPEND PROPERTY LINK_DEPENDS
    "${CMAKE_SOURCE_DIR}/STM32F103XX_FLASH.ld")

# Add STM32CubeMX generated sources
add_subdirectory(cmake/stm32cubemx)
include(cmake/key_crypto.cmake)

# Link directories setup
target_link_directories(${CMAKE_PROJECT_NAME} PRIVATE
    # Add user defined library search paths
)

# Add sources to executable
target_sources(${CMAKE_PROJECT_NAME} PRIVATE
    Core/Src/ctaphid.c
    Core/Src/ctap_dispatch.c
    Core/Src/key_cbor.c
    Core/Src/ctap_request.c
    Core/Src/key_presence.c
    Core/Src/key_authdata.c
    Core/Src/ctap_credential.c
    Core/Src/key_vault.c
    Core/Src/key_journal.c
    Core/Src/key_root.c
    Core/Src/key_random.c
    Core/Src/key_backend.c
    Core/Src/board_keys.c
    Core/Src/key_sd_readonly.c
    Core/Src/key_otp.c
    USB_DEVICE/App/fido_usb.c
)

# Add include paths
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
    # Add user defined include paths
)

# Add project symbols (macros)
target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE
    # Add user defined symbols
)

# Remove wrong libob.a library dependency when using cpp files
list(REMOVE_ITEM CMAKE_C_IMPLICIT_LINK_LIBRARIES ob)

# Add linked libraries
target_link_libraries(${CMAKE_PROJECT_NAME}
    stm32cubemx

    # Add user defined libraries
)
foreach(api make assert digest)
    target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "-Wl,--undefined=key_authdata_${api}")
endforeach()
target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "-Wl,--undefined=ctap_credential_jobs")
target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "-Wl,--undefined=ctap_credential_presence_progress")
foreach(api seal open)
    target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "-Wl,--undefined=key_vault_${api}")
endforeach()
foreach(api recover provision reserve dispose matches)
    target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "-Wl,--undefined=key_journal_${api}")
endforeach()
foreach(api encode decode)
    target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "-Wl,--undefined=key_root_${api}")
endforeach()
foreach(api boot ready bound epoch remaining bytes private stop)
    target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "-Wl,--undefined=key_random_${api}")
endforeach()
foreach(api init dispose ops)
    target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "-Wl,--undefined=key_backend_${api}")
endforeach()
foreach(api begin sample sample_inputs cancel consume reset progress)
    target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "-Wl,--undefined=key_presence_${api}")
endforeach()

# Retain the real OTP implementation in resource measurements even before RTC
# and private-data UI integration. This does not execute or provision it.
foreach(api hotp totp)
    target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "-Wl,--undefined=key_otp_${api}")
endforeach()
