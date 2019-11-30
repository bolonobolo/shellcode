
tasm32.exe -m5 wasm.asm
tlink32.exe -x wasm,wasm.dat
@del *.obj

