add_rules("mode.debug", "mode.release")
set_languages("c++17")

add_requires("libevdev")

target("inputtino")
    set_kind("$(kind)")
    add_files("src/uinput/*.cpp") -- TODO: DualSense/PS5 controller (uhid)
    add_headerfiles("include/inputtino/*.hpp", "include/inputtino/*.h")
    add_includedirs("include")
    add_packages("libevdev")

