
workspace "stb_rect_pack"
	configurations {"Debug", "Release"}
	architecture "x64"
	location "build"
	objdir "build/obj"
	targetdir "lib"
	
project "stb_rect_pack"
	kind "StaticLib"
	language "C"
	
	flags "NoIncrementalLink"
	
	files "src/stb_rect_pack.c"
	
	staticruntime "On"
	runtime "Release"
	
	filter "configurations:Debug"
		symbols "On"
	
	filter "configurations:Release"
		optimize "On"
		symbols "Off"
	
	filter {}
