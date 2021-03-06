cmake_minimum_required(VERSION 3.1 FATAL_ERROR)
include(GenerateExportHeader)
include(GNUInstallDirs)

project(Zydis VERSION 2.0)

# =============================================================================================== #
# Overridable options                                                                             #
# =============================================================================================== #

# Features
option(ZYDIS_FEATURE_DECODER
    "Enable instruction decoding and formtting functionality"
    ON)
option(ZYDIS_FEATURE_ENCODER
    "Enable instruction encoding functionality"
    OFF)
option(ZYDIS_FEATURE_EVEX 
    "Enable support for EVEX instructions" 
    ON)
option(ZYDIS_FEATURE_MVEX 
    "Enable support for MVEX instructions" 
    ON)
option(ZYDIS_FEATURE_FLAGS 
    "Include information about affected flags"
    ON)
option(ZYDIS_FEATURE_CPUID 
    "Include information about CPUID feature-flags"
    OFF)

# Build configuration
option(ZYDIS_BUILD_EXAMPLES 
    "Build examples" 
    ON)
option(ZYDIS_BUILD_TOOLS 
    "Build tools" 
    ON)
option(ZYDIS_DEV_MODE
    "Enable developer mode (-Wall, -Werror, ...)"
    OFF)

# =============================================================================================== #
# Developer mode                                                                                  #
# =============================================================================================== #

# If in developer mode, hack global compiler flags.
if (ZYDIS_DEV_MODE)
    set_property(GLOBAL PROPERTY USE_FOLDERS ON)
    if ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU" OR
            "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR
            "${CMAKE_C_COMPILER_ID}" STREQUAL "AppleClang")
        set(compiler_specific "-pedantic -Wextra -Werror")
    elseif (MSVC)
        set(compiler_specific "/WX /W4 /TC")
    endif ()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${compiler_specific}"
        CACHE STRING "Flags used by the compiler during all build types." FORCE)
endif ()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

# =============================================================================================== #
# Library configuration                                                                           #
# =============================================================================================== #

add_library("Zydis")

target_include_directories("Zydis" 
    PUBLIC "include" ${PROJECT_BINARY_DIR}
    PRIVATE "src")
target_compile_definitions("Zydis" PRIVATE "_CRT_SECURE_NO_WARNINGS" "ZYDIS_EXPORTS")
generate_export_header("Zydis" BASE_NAME "ZYDIS" EXPORT_FILE_NAME "ZydisExportConfig.h")

if (NOT ZYDIS_FEATURE_ENCODER AND NOT ZYDIS_FEATURE_DECODER)
	message(
		FATAL_ERROR
		"\nIt's dangerous to go alone! Take at least one of these:\n"
		"[ ] ZYDIS_FEATURE_ENCODER [ ] ZYDIS_FEATURE_DECODER"
	)
endif ()

if (ZYDIS_FEATURE_EVEX)
    target_compile_definitions("Zydis" PUBLIC "ZYDIS_ENABLE_FEATURE_EVEX")
endif ()
if (ZYDIS_FEATURE_MVEX)
    target_compile_definitions("Zydis" PUBLIC "ZYDIS_ENABLE_FEATURE_MVEX")
endif ()
if (ZYDIS_FEATURE_FLAGS)
    target_compile_definitions("Zydis" PUBLIC "ZYDIS_ENABLE_FEATURE_FLAGS")
endif ()
if (ZYDIS_FEATURE_CPUID)
    target_compile_definitions("Zydis" PUBLIC "ZYDIS_ENABLE_FEATURE_CPUID")
endif ()
if (ZYDIS_FEATURE_DECODER)
    target_compile_definitions("Zydis" PUBLIC "ZYDIS_ENABLE_FEATURE_DECODER")
endif ()
if (ZYDIS_FEATURE_ENCODER)
    target_compile_definitions("Zydis" PUBLIC "ZYDIS_ENABLE_FEATURE_ENCODER")
endif ()

target_sources("Zydis"
    PUBLIC
        "${CMAKE_CURRENT_LIST_DIR}/include/Zydis/CommonTypes.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/Zydis/Defines.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/Zydis/Mnemonic.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/Zydis/Register.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/Zydis/SharedTypes.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/Zydis/Status.h"       
        "${CMAKE_CURRENT_LIST_DIR}/include/Zydis/Utils.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/Zydis/Zydis.h"
    PRIVATE
        "src/Mnemonic.c"
        "src/Register.c"
        "src/SharedData.h"
        "src/SharedData.c"
        "src/Utils.c"
        "src/Zydis.c")

if (ZYDIS_FEATURE_DECODER)
    target_sources("Zydis" 
        PUBLIC 
            "${CMAKE_CURRENT_LIST_DIR}/include/Zydis/Decoder.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/Zydis/DecoderTypes.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/Zydis/Formatter.h"
        PRIVATE 
            "src/DecoderData.h"
            "src/Decoder.c"
            "src/DecoderData.c"
            "src/Formatter.c")
endif ()

if (ZYDIS_FEATURE_ENCODER)
    target_sources("Zydis" 
        PUBLIC 
            "${CMAKE_CURRENT_LIST_DIR}/include/Zydis/Encoder.h" 
        PRIVATE 
            "src/EncoderData.h"
            "src/Encoder.c"
            "src/EncoderData.c")
endif ()

if (BUILD_SHARED_LIBS AND WIN32)
    target_sources("Zydis" PRIVATE "src/VersionInfo.rc")
endif ()

# TODO: Install CMake config.
install(TARGETS "Zydis"
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY "include" DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# =============================================================================================== #
# Examples                                                                                        #
# =============================================================================================== #

if (ZYDIS_BUILD_EXAMPLES)
	if (ZYDIS_FEATURE_DECODER)
		add_executable("FormatterHooks" 
			"examples/FormatterHooks.c"
			"examples/FormatHelper.h")
		target_link_libraries("FormatterHooks" "Zydis")
		set_target_properties("FormatterHooks" PROPERTIES FOLDER "Examples/Formatter")
		target_compile_definitions("FormatterHooks" PRIVATE "_CRT_SECURE_NO_WARNINGS")

        add_executable("ZydisFuzzIn" "examples/ZydisFuzzIn.c")
        target_link_libraries("ZydisFuzzIn" "Zydis")
        set_target_properties("FormatterHooks" PROPERTIES FOLDER "Examples")
        target_compile_definitions("ZydisFuzzIn" PRIVATE "_CRT_SECURE_NO_WARNINGS")

        if (${CMAKE_SYSTEM_NAME} STREQUAL "Darwin" OR ${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
            add_executable("ZydisPerfTest" "examples/ZydisPerfTest.c")
            target_link_libraries("ZydisPerfTest" "Zydis")
            set_target_properties("FormatterHooks" PROPERTIES FOLDER "Examples")
            target_compile_definitions("ZydisPerfTest" PRIVATE "_CRT_SECURE_NO_WARNINGS")
        endif ()
	endif ()
endif ()

# =============================================================================================== #
# Tools                                                                                           #
# =============================================================================================== #

if (ZYDIS_BUILD_TOOLS)
	if (ZYDIS_FEATURE_DECODER)
		add_executable("ZydisDisasm" "tools/ZydisDisasm.c")
		target_link_libraries("ZydisDisasm" "Zydis")
		set_target_properties ("ZydisDisasm" PROPERTIES FOLDER "Tools")
		target_compile_definitions("ZydisDisasm" PRIVATE "_CRT_SECURE_NO_WARNINGS")

        add_executable("ZydisInfo" "tools/ZydisInfo.c")
        target_link_libraries("ZydisInfo" "Zydis")
        set_target_properties ("ZydisInfo" PROPERTIES FOLDER "Tools")
        target_compile_definitions("ZydisInfo" PRIVATE "_CRT_SECURE_NO_WARNINGS")
	endif ()
endif ()
