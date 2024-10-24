package("inputtino")
    set_kind("library")
    set_homepage("https://github.com/games-on-whales/inputtino")
    set_description("A virtual input library")
    set_license("MIT")

    set_urls("https://github.com/games-on-whales/inputtino.git")

    add_deps("cmake", "libevdev")

    add_includedirs("include")

    on_install("linux", function(package)
        local configs = {}
        os.cp(path.join(package:scriptdir(), "port", "xmake.lua"), "xmake.lua")
        import("package.tools.xmake").install(package, configs)
    end)
