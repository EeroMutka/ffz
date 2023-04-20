
workspace "stb_image"
	configurations {"Debug", "Release"}
	architecture "x64"
	location "build"
	objdir "build/obj"
	targetdir "lib"
	
project "stb_image"
	kind "StaticLib"
	language "C"
	
	flags "NoIncrementalLink"
	
	files "src/stb_image.c"
	
	staticruntime "On"
	runtime "Release"
	
	filter "configurations:Debug"
		symbols "On"
	
	filter "configurations:Release"
		optimize "On"
		symbols "Off"
	
	filter {}
