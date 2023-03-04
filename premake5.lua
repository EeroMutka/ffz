
function apply_defaults()
	cdialect "C11"
	
	debugdir "%{cfg.linktarget.directory}"
	flags {"FatalWarnings"}
	includedirs "."

	filter "configurations:Debug"
		defines { "_DEBUG" }
		symbols "On"
		
	filter "configurations:Release"
		defines { "_RELEASE" }
		optimize "On"
	
	filter "system:windows"
		linkoptions { "/DYNAMICBASE:NO" }
	
	filter {}
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
	
	apply_defaults()
	
	files {
		"src/*",
		"src/foundation/*",
	}
	
	-- build with tb?
	if false then
		defines "FFZ_BACKEND_TB"
		
		includedirs {
			"Cuik/tb/include",
			"Cuik/tb/src",
			"Cuik/common",
			"Cuik/c11threads",
		}
		
		files {
			"Cuik/LibCuik/lib/tls.c", -- ??????
			
			-- TB source files
			--"Cuik/Common/*",
			"Cuik/c11threads/threads_msvc.c",
			"Cuik/Common/common.c",
			"Cuik/tb/include/*",
			"Cuik/tb/src/**",
		}
		
		disablewarnings { "4018", "4267", "4267", "4244", "4013", "4334", "4146" }
	end
	
	-- build with gmmc?
	if true then
		defines {
			"FFZ_BACKEND_GMMC",
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

