
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
	objdir "build/bin"

project "ffz"
	kind "ConsoleApp"
	language "C++"
	
	apply_defaults()
	
	links {
		"src/Cuik/tb/tb.lib",
	}
	
	files {
		"src/*",
		"src/foundation/*",
		"src/Cuik/tb/include/tb.h",
	}

