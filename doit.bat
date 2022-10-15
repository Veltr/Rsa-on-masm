@echo off

set file=rsa

ml.exe /c /coff %file%.obj
link.exe /subsystem:console %file%.obj

pause