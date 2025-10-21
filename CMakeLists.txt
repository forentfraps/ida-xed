cmake_minimum_required(VERSION 3.20)
project(ida_xed_plugin LANGUAGES CXX)

foreach(VAR IN ITEMS IDA_SDK XED_ROOT IDA_LIBROOT)
  if(NOT DEFINED ${VAR} OR "${${VAR}}" STREQUAL "")
    message(FATAL_ERROR
      "Missing required cache var: ${VAR}\n"
      "Example: -D${VAR}=C:/path/to/... (use forward slashes)")
  endif()
endforeach()

add_library(plugin SHARED
  src/main.cpp
)

target_include_directories(plugin PRIVATE
  "${IDA_SDK}/include"
  "${XED_ROOT}/include"
)

target_link_directories(plugin PRIVATE
  "${XED_ROOT}/lib"
  "${IDA_LIBROOT}"
)

target_link_libraries(plugin PRIVATE
  xed
  xed-ild
  idalib
  ida
)

target_compile_definitions(plugin PRIVATE
  __NT__ __EA64__ __X64__
)

if(MSVC)
  target_compile_options(plugin PRIVATE
    /EHsc /Zi /MD /permissive- /nologo
    /d1reportSingleClassLayoutidainfo
    /d1reportSingleClassLayoutsegment_t
    /d1reportSingleClassLayoutinsn_t
    /d1reportSingleClassLayoutasm_t
    /d1reportSingleClassLayoutprocessor_t
    /d1reportSingleClassLayoutplugin_t
  )
  set_property(TARGET plugin PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")

  if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "This project must be configured for 64-bit. Use: -A x64")
  endif()
endif()

set_target_properties(plugin PROPERTIES
  OUTPUT_NAME "ida-xed"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)
