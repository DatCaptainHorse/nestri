add_rules("mode.release", "mode.debug")
set_languages("c++23")

add_requires("libhv 1.3.2", "jwt-cpp v0.7.0", "jsoncons v0.170.2")

includes("inputtino.lua")
add_requires("inputtino")

target("inputtino-server")
	set_kind("binary")
	add_files("Source/*.cpp", "Source/*.cppm")
	add_packages("libhv", "jwt-cpp", "jsoncons", "inputtino")
    -- If Linux, we want to use clang as it has better modules support
    if is_plat("linux") then
        set_toolchains("clang")
        add_cxxflags("-stdlib=libc++")
        add_links("c++")
    end
