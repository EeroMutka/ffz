
workspace "raylib"
	configurations {"Debug", "Release"}
	architecture "x64"
	location "build"
	objdir "build/obj"
	targetdir "."
	
project "raylib"
	kind "StaticLib"
	language "C"
	toolset "clang"
	
	flags "NoIncrementalLink"
	defines "PLATFORM_DESKTOP"
	defines "GRAPHICS_API_OPENGL_33"
	defines "MAX_PATH=260"
	
	includedirs {
		"src",
		"src/external",
		"src/external/glfw/include",
	}
	
	files {
		"src/*",
	}
	
	staticruntime "On"
	runtime "Release"
	
	--links {"winmm", "kernel32", "opengl32", "gdi32"}
	--links {"winmm"}
	
	filter "configurations:Debug"
		--defines { "_DEBUG" }
		symbols "On"
	--	
	filter "configurations:Release"
		--defines { "_RELEASE" }
		optimize "On"
		symbols "Off"
	
	--filter "system:windows"
	--	linkoptions { "/DYNAMICBASE:NO" }
	filter {}
