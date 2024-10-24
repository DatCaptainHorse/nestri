# SOURCE: https://github.com/games-on-whales/wolf #

add_library(fake_udev_lib STATIC)
add_library(fake-udev::lib ALIAS fake_udev_lib)
target_include_directories(fake_udev_lib PUBLIC .)
target_sources(fake_udev_lib
  PUBLIC fake-udev/fake-udev.hpp fake-udev/MurmurHash2.h
  PRIVATE fake-udev/MurmurHash2.cpp
)
target_compile_features(fake_udev_lib PRIVATE cxx_std_17)
