# hash functions, including cryptographic
add_library (hash STATIC)
add_library (Crypto::hash ALIAS hash)

add_library (crypto STATIC)
add_library (Crypto::crypto ALIAS crypto)

set_target_properties (hash PROPERTIES
  OUTPUT_NAME "crypto_hash"
)

set_target_properties (crypto PROPERTIES
  OUTPUT_NAME "crypto_crypto"
)

target_include_directories (
  hash

  INTERFACE

  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated/>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_sources (
  hash

  PRIVATE

  ../sv/utiltime.cpp
  ../sv/fs.cpp
  ../sv/crypto/chacha20.cpp
  ../sv/crypto/hmac_sha512.cpp
  ../sv/crypto/ripemd160.cpp
  ../sv/crypto/sha1.cpp
  ../sv/crypto/sha256.cpp
  ../sv/crypto/sha512.cpp
  ../sv/support/cleanse.cpp
)

target_compile_features (hash PUBLIC cxx_std_23)
set_target_properties (hash PROPERTIES CXX_EXTENSIONS ON)

target_link_libraries (
  hash

  PUBLIC

  Data::numbers
  OpenSSL::SSL
  OpenSSL::Crypto
  PkgConfig::cryptopp

)

target_include_directories (
  crypto

  INTERFACE

  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated/>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_sources (
  crypto

  PRIVATE

  secret_share.cpp
  block.cpp
)

target_compile_features (crypto PUBLIC cxx_std_23)
set_target_properties (crypto PROPERTIES CXX_EXTENSIONS ON)

target_link_libraries (
  crypto

  PUBLIC

  Crypto::hash
  Data::data
)

configure_file (
    ${PROJECT_SOURCE_DIR}/include/crypto/version.hpp.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated/crypto/version.hpp
)

get_target_property (OUT Crypto::crypto LINK_LIBRARIES)

include (GNUInstallDirs)

# copy include directory into install destination
install (
  DIRECTORY ${PROJECT_SOURCE_DIR}/include/
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install (
  TARGETS crypto hash
  EXPORT CryptoTargets
  ARCHIVE
)

install (
  FILES ${CMAKE_CURRENT_BINARY_DIR}/generated/crypto/version.hpp
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/crypto
)

install (
  EXPORT CryptoTargets
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/crypto
  FILE cryptoTargets.cmake
  NAMESPACE Crypto::
)

include (CMakePackageConfigHelpers)

# generate the config file that includes the exports
configure_package_config_file (${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/dataConfig.cmake"
  INSTALL_DESTINATION "lib/cmake/dataFunctions"
  NO_SET_AND_CHECK_MACRO
  NO_CHECK_REQUIRED_COMPONENTS_MACRO
)

write_basic_package_version_file (
  "${CMAKE_CURRENT_BINARY_DIR}/dataConfigVersion.cmake"
  COMPATIBILITY AnyNewerVersion
)

install (FILES
  ${CMAKE_CURRENT_BINARY_DIR}/dataConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/dataConfigVersion.cmake
  DESTINATION lib/cmake/data
)

set (CPACK_PACKAGE_VENDOR "Daniel Krawisz")
set (CPACK_PACKAGE_CONTACT "email@example.com")
set (CPACK_PACKAGE_DESCRIPTION "WhatsOnChain API")
include (CPack)

include(GNUInstallDirs)
