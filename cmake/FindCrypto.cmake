find_package (PkgConfig)
pkg_check_modules (PC_CRYPTO QUIET Crypto)

find_path(CRYPTO_INCLUDE_DIR
NAMES crypto.hpp
HINTS ENV CRYPTO_INC_DIR
      ENV CRYPTO_DIR
      $ENV{CRYPTO_DIR}/include
PATH_SUFFIXES include/crypto
  DOC "The directory containing the Crypto header files"
)

find_library (CRYPTO_LIBRARY NAMES crypto
  HINTS ENV CRYPTO_LIB_DIR
  ENV CRYPTO_DIR
  $ENV{CRYPTO_DIR}/lib
  PATH_SUFFIXES lib/crypto
  DOC "Path to the Crypto library"
)

message (STATUS "${CRYPTO_INCLUDE_DIR}")
if (CRYPTO_INCLUDE_DIR)
    file (READ "${CRYPTO_INCLUDE_DIR}/crypto/version.hpp" ver)
    string (REGEX MATCH "#define CRYPTO_VERSION \"([0-9*.]*)\"" _ ${ver})
    set (CRYPTO_VERSION ${CMAKE_MATCH_1})
endif ()

include (FindPackageHandleStandardArgs)
find_package_handle_standard_args (Crypto
  FOUND_VAR CRYPTO_FOUND
  REQUIRED_VARS
    CRYPTO_LIBRARY
    CRYPTO_INCLUDE_DIR
  VERSION_VAR CRYPTO_VERSION
)

if (CRYPTO_FOUND)
  set (CRYPTO_LIBRARIES ${CRYPTO_LIBRARY})
  set (CRYPTO_INCLUDE_DIRS ${CRYPTO_INCLUDE_DIR})
endif ()

if (CRYPTO_FOUND AND NOT TARGET Crypto::crypto)
  add_library (Crypto::Crypto UNKNOWN IMPORTED)
  set_target_properties (Crypto::Crypto PROPERTIES
    IMPORTED_LOCATION "${CRYPTO_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${CRYPTO_INCLUDE_DIR}"
  )
endif ()

mark_as_advanced (
  CRYPTO_INCLUDE_DIR
  CRYPTO_LIBRARY
)
