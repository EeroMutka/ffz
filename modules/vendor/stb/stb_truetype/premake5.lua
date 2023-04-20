
workspace "stb_truetype"
	configurations {"Debug", "Release"}
	architecture "x64"
	location "build"
	objdir "build/obj"
	targetdir "lib"
	
project "stb_truetype"
	kind "StaticLib"
	language "C"
	
	flags "NoIncrementalLink"
	
	files "src/stb_truetype.c"
	
	staticruntime "On"
	runtime "Release"
	
	filter "configurations:Debug"
		symbols "On"
	
	filter "configurations:Release"
		optimize "On"
		symbols "Off"
	
	filter {}
