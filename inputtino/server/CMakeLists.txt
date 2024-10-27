cmake_minimum_required(VERSION 3.28)

project(inputtino-server VERSION 0.1 LANGUAGES CXX)

include(FetchContent)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

### DEPS ###
FetchContent_Declare(
  inputtino
  GIT_REPOSITORY https://github.com/games-on-whales/inputtino.git
  GIT_TAG "stable")
FetchContent_MakeAvailable(inputtino)

FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY "https://github.com/nlohmann/json.git"
  GIT_TAG "v3.11.3"
)
FetchContent_MakeAvailable(nlohmann_json)

FetchContent_Declare(
  jwt-cpp
  GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
  GIT_TAG "v0.7.0")
set(JWT_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(jwt-cpp)

FetchContent_Declare(
  scnlib
  GIT_REPOSITORY https://github.com/eliaskosunen/scnlib.git
  GIT_TAG "v3.0.1")
set(SCN_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SCN_DOCS OFF CACHE BOOL "" FORCE)
set(SCN_TESTS OFF CACHE BOOL "" FORCE)
set(SCN_FUZZING OFF CACHE BOOL "" FORCE)
set(SCN_BENCHMARKS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(scnlib)

FetchContent_Declare(
  libhv
  GIT_REPOSITORY "https://github.com/ithewei/libhv.git"
  GIT_TAG "v1.3.3")
set(BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(BUILD_FOR_MT ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(libhv)

add_subdirectory(External/fake-udev)
### EOF DEPS ###

add_executable(inputtino-server)
target_sources(inputtino-server PRIVATE
  Source/main.cpp
)
target_link_libraries(inputtino-server PRIVATE
  inputtino::libinputtino
  hv_static
  jwt-cpp::jwt-cpp
  nlohmann_json
  fake-udev::lib
  scn::scn
)
