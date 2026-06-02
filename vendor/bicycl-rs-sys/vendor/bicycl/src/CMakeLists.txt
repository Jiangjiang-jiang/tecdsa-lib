set (BICYCL_MAIN_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/bicycl.hpp)
set (BICYCL_INSTALLABLE_HEADERS_AND_INL
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/seclevel.hpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/seclevel.inl
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/arith/gmp_extras.hpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/arith/gmp_extras.inl
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/arith/openssl_wrapper.hpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/arith/openssl_wrapper.inl
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/arith/qfi.hpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/arith/qfi.inl
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/cl/CL_HSM_utils.hpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/cl/CL_HSM_utils.inl
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/cl/CL_HSMqk.hpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/cl/CL_HSMqk.inl
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/cl/CL_HSM2k.hpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/cl/CL_HSM2k.inl
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/cl/CL_DL_proof.hpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/cl/CL_DL_proof.inl
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/cl/CL_threshold.hpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/cl/CL_threshold.inl
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/ec/ecdsa.hpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/ec/ecdsa.inl
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/ec/threshold_ECDSA.hpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/ec/threshold_ECDSA.inl
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/ec/twoParty_ECDSA.hpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/ec/twoParty_ECDSA.inl
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/ec/proofs.hpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/ec/proofs.inl
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/ec/signature.hpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/ec/signature.inl
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/Paillier.hpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/Paillier.inl
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/Joye_Libert.hpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/Joye_Libert.inl
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/parallelism.hpp
                      )
add_library (bicycl INTERFACE)
target_sources (bicycl INTERFACE ${BICYCL_MAIN_HEADER}
                                    ${BICYCL_INSTALLABLE_HEADERS_AND_INL})
target_include_directories (bicycl INTERFACE
                              $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
                              $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_link_libraries (bicycl INTERFACE gmp::gmp OpenSSL::Crypto)
if (THREADS_FOUND AND CMAKE_USE_PTHREADS_INIT)
  target_link_libraries (bicycl INTERFACE Threads::Threads)
  target_compile_definitions (bicycl INTERFACE BICYCL_WITH_PTHREADS)
endif ()

install (TARGETS bicycl EXPORT bicyclExport
                          RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
                          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
                          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install (FILES ${BICYCL_MAIN_HEADER}
                          DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install (DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/
                          DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/bicycl
                          FILES_MATCHING PATTERN "*.hpp" PATTERN "*.inl")
