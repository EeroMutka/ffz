cl /Z7 /GS- /c raylib_demo.c

link /DEFAULTLIB:MSVCRTD /DEFAULTLIB:OLDNAMES /DEBUG /subsystem:console "raylib\raylib.lib" user32.lib kernel32.lib shell32.lib winmm.lib gdi32.lib raylib_demo.obj