configure_file (${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in
                ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)

find_program (DOXYGEN doxygen)

set (MSG "The documentation cannot be build as CMake failed to find doxygen \
during the configuration step. If you want to build the documentation, you \
need to install doxygen and re-run the configuration step of CMake.")
set (DOXYGEN_MIN_VERSION "1.9.5")

if (NOT DOXYGEN)
  message (STATUS "Warning, will not be able to build doc: doxygen not found")
  add_custom_target (doc COMMAND ${CMAKE_COMMAND} -E echo ${MSG})
else ()
  execute_process(COMMAND ${DOXYGEN} -v OUTPUT_VARIABLE DOXYGEN_VERSION_RAW)
  string(REGEX REPLACE "\n" "" DOXYGEN_VERSION ${DOXYGEN_VERSION_RAW})
  if(DOXYGEN_VERSION VERSION_GREATER_EQUAL DOXYGEN_MIN_VERSION)
    message (STATUS "Found Doxygen: ${DOXYGEN_VERSION}")
    add_custom_target (doc COMMAND ${DOXYGEN} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
  else()
    message (STATUS "Warning, will not be able to build doc: found doxygen \
but with version ${DOXYGEN_VERSION} < ${DOXYGEN_MIN_VERSION}")
    add_custom_target (doc COMMAND ${CMAKE_COMMAND} -E echo ${MSG})
  endif()
endif ()
