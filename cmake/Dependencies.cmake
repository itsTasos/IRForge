# Exact archive versions and hashes; restore remains a build-time operation.
if(CMAKE_VERSION VERSION_GREATER_EQUAL 4.0)
  set(CMAKE_POLICY_VERSION_MINIMUM 3.5) # yaml-cpp 0.8.0 declares an older minimum.
endif()
set(IRFORGE_DEPS "${CMAKE_SOURCE_DIR}/build/dependencies" CACHE PATH "Pinned dependency restore directory")
function(irforge_archive name url hash localFile)
  if(EXISTS "${IRFORGE_DEPS}/${localFile}")
    set(url "${IRFORGE_DEPS}/${localFile}")
  endif()
  FetchContent_Declare(${name} URL "${url}" URL_HASH "SHA256=${hash}" DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
endfunction()
irforge_archive(sqlite "https://sqlite.org/2026/sqlite-amalgamation-3530400.zip"
  1e71ddf93849c6a6ecf58b827c0692073d2dd7ee40196158068f7b29f422e87d sqlite.zip)
FetchContent_MakeAvailable(sqlite)
add_library(irforge_sqlite STATIC "${sqlite_SOURCE_DIR}/sqlite3.c")
target_include_directories(irforge_sqlite PUBLIC "${sqlite_SOURCE_DIR}")
target_compile_definitions(irforge_sqlite PRIVATE SQLITE_THREADSAFE=1 SQLITE_DQS=0 SQLITE_DEFAULT_FOREIGN_KEYS=1
  SQLITE_OMIT_LOAD_EXTENSION SQLITE_ENABLE_API_ARMOR)
irforge_archive(tinyxml2 "https://github.com/leethomason/tinyxml2/archive/refs/tags/11.0.0.zip"
  1c35b8d8a586125d5e43380fd2137abbfde645183ed1641f86c815359320412f tinyxml2.zip)
set(tinyxml2_BUILD_TESTING OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(tinyxml2)
irforge_archive(yamlcpp "https://github.com/jbeder/yaml-cpp/archive/refs/tags/0.8.0.zip"
  334e80ab7b52e14c23f94e041c74bab0742f2281aad55f66be2f19f4b7747071 yamlcpp.zip)
set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
set(YAML_CPP_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(yamlcpp)
