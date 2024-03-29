
function import_ffz()
	cdialect "C99"
	
	debugdir "%{cfg.linktarget.directory}"
	flags {"FatalWarnings"}
	includedirs "."
	
	vectorextensions "AVX"
	
	defines {
		"F_DEF_TRAP_TITLE=\"Error!\"",
		"F_DEF_TRAP_MESSAGE=\"FFZ reached an internal error. Sorry! Please message Eero.\"",
	}
	
	filter "configurations:Debug"
		defines { "F_DEBUG" }
		symbols "On"
		
	filter "configurations:Profile"
		files "src/tracy/TracyClient.cpp"
		
		defines { "TRACY_ENABLE", "TRACY_NO_EXIT" }
		editandcontinue "Off" -- tracy requires edit-and-continue to be off
		optimize "On"
		
	filter "configurations:Release"
		--defines { "_RELEASE" }
		optimize "On"
	
	filter "system:windows"
		linkoptions { "/DYNAMICBASE:NO" } -- deterministic addresses
	
	filter {}
	
	-- include tb backend?
	if false then
		defines "FFZ_BUILD_INCLUDE_TB"
		
		-- THIS IS TEMPORARY!
		links "C:/dev/Cuik/tb/tb"
		includedirs "C:/dev/Cuik/tb/include"
		files "C:/dev/Cuik/c11threads/threads_msvc.c"
		files "C:/dev/Cuik/common/common.c"
		
		--includedirs {
		--	"Cuik/tb/include",
		--	"Cuik/tb/src",
		--	"Cuik/common",
		--	"Cuik/c11threads",
		--}
		--
		--files {
		--	"Cuik/LibCuik/lib/tls.c", -- ??????
		--	
		--	-- TB source files
		--	--"Cuik/Common/*",
		--	"Cuik/c11threads/threads_msvc.c",
		--	"Cuik/Common/common.c",
		--	"Cuik/tb/include/*",
		--	"Cuik/tb/src/**",
		--}
		--
		--disablewarnings { "4018", "4267", "4267", "4244", "4013", "4334", "4146" }
		disablewarnings { "4200" }
	end
	
	-- include gmmc backend?
	if true then
		defines "FFZ_BUILD_INCLUDE_GMMC"
		defines {
			"ZYDIS_STATIC_BUILD",
			"ZYCORE_STATIC_BUILD",
		}
		
		includedirs {
			"gmmc/zydis/include",
			"gmmc/zydis/src",
			"gmmc/zydis/zycore/include",
		}
		
		files {
			"gmmc/*",
			"gmmc/zydis/src/*",
			"gmmc/zydis/zycore/src/**",
		}
	end
end

workspace "ffz"
	configurations { "Debug", "Profile", "Release" }
	architecture "x64"
	exceptionhandling "Off"
	rtti "Off"
	
	location "build"
	targetdir "bin"

project "ffz"
	kind "ConsoleApp"
	language "C++"
	
	-- clang
	--toolset "clang"
	--buildoptions "-Wformat" -- tracy needs this
	
	import_ffz()
	
	files {
		"src/*",
		"src/foundation/*",
		"src/ffz_console_tools/ffz.c",
	}

project "ffz_test_runner"
	kind "ConsoleApp"
	language "C++"
	
	import_ffz()
	
	files {
		"src/*",
		"src/foundation/*",
		"src/ffz_console_tools/ffz_test_runner.cpp",
	}

