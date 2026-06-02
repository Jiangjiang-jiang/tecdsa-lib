add_custom_target (examples COMMAND ${CMAKE_COMMAND} -E sleep 0)

add_executable (chia-vdf chia-vdf.cpp)
target_link_libraries (chia-vdf PUBLIC bicycl)
add_dependencies (examples chia-vdf)

add_executable (CL_HSMqk_setup CL_HSMqk_setup.cpp)
target_link_libraries (CL_HSMqk_setup PUBLIC bicycl)
add_dependencies (examples CL_HSMqk_setup)

add_executable (CL_HSM2k_setup CL_HSM2k_setup.cpp)
target_link_libraries (CL_HSM2k_setup PUBLIC bicycl)
add_dependencies (examples CL_HSM2k_setup)

add_executable (CL_HSMqk_example CL_HSMqk_example.cpp)
target_link_libraries (CL_HSMqk_example PUBLIC bicycl)
add_dependencies (examples CL_HSMqk_example)

add_executable (CL_threshold_example CL_threshold_example.cpp)
target_link_libraries (CL_threshold_example PUBLIC bicycl)
add_dependencies (examples CL_threshold_example)

add_executable (TwoPartyECDSA_example TwoPartyECDSA_example.cpp)
target_link_libraries (TwoPartyECDSA_example PUBLIC bicycl)
add_dependencies (examples TwoPartyECDSA_example)

add_executable (TwoPartyECDSA_localhost_P1 TwoPartyECDSA_localhost_P1.cpp)
target_link_libraries (TwoPartyECDSA_localhost_P1 PUBLIC bicycl)
add_dependencies (examples TwoPartyECDSA_localhost_P1)

add_executable (TwoPartyECDSA_localhost_P2 TwoPartyECDSA_localhost_P2.cpp)
target_link_libraries (TwoPartyECDSA_localhost_P2 PUBLIC bicycl)
add_dependencies (examples TwoPartyECDSA_localhost_P2)
