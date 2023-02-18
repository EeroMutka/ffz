
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
	
	--links "Cuik/tb/tb.lib"
	includedirs { "Cuik/tb/include", "Cuik/common" }
	
	-- disable warnings required to make TB build
	disablewarnings { "4018", "4267", "4267", "4244", "4013", "4334", "4146" }
	
	files {
		"src/*",
		"src/foundation/*",
		
		-- TB source files
		--"Cuik/Common/*",
		"Cuik/tb/include/*",
		"Cuik/tb/src/**",
		
		--[[
		"Cuik/tb/src/debug_builder.c",
		"Cuik/tb/src/exporter.c",
		"Cuik/tb/src/hash.c",
		"Cuik/tb/src/ir_printer.c",
		"Cuik/tb/src/iter.c",
		"Cuik/tb/src/symbols.c",
		"Cuik/tb/src/tb.c",
		"Cuik/tb/src/tb_analysis.c",
		"Cuik/tb/src/tb_atomic.c",
		"Cuik/tb/src/tb_builder.c",
		"Cuik/tb/src/tb_internal.c",
		"Cuik/tb/src/tb_jit.c",
		"Cuik/tb/src/tb_optimizer.c",
		"Cuik/tb/src/validator.c",
		"Cuik/tb/src/codegen/tree.c",
		"Cuik/tb/src/bigint/BigInt.c",
		"Cuik/tb/src/objects/coff.c",
		"Cuik/tb/src/objects/coff_parse.c",
		"Cuik/tb/src/objects/elf64.c",
		"Cuik/tb/src/objects/export_helper.c",
		"Cuik/tb/src/objects/macho.c",
		"Cuik/tb/src/objects/wasm_obj.c",
		"Cuik/tb/src/linker/elf.c",
		"Cuik/tb/src/linker/linker.c",
		"Cuik/tb/src/linker/pe.c",
		"Cuik/tb/src/system/posix.c",
		"Cuik/tb/src/system/win32.c",
		"Cuik/tb/src/debug/cv/cv.c",
		"Cuik/tb/src/debug/cv/cv_type_builder.c",
		"Cuik/tb/src/opt/branchless.c",
		"Cuik/tb/src/opt/canonical.c",
		"Cuik/tb/src/opt/copy_elision.c",
		"Cuik/tb/src/opt/dead_code_elim.c",
		"Cuik/tb/src/opt/deshort_circuit.c",
		"Cuik/tb/src/opt/hoist_locals.c",
		"Cuik/tb/src/opt/load_elim.c",
		"Cuik/tb/src/opt/mem2reg.c",
		"Cuik/tb/src/opt/merge_ret.c",
		"Cuik/tb/src/opt/refinement.c",
		"Cuik/tb/src/x64/x64.c",
		"Cuik/tb/src/x64/x64_new.c",]]--
	}

