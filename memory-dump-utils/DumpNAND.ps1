echo "Plug in Switch via usb-c in RCM mode to begin key dump"
echo "Once the keydump payload has completed, switch off the switch and restart into RCM mode"


Tools\TegraRcmSmash.exe -w Tools\biskeydump.bin BOOT:0x0 > prod.keys
<#
This runs the commandline version of tegrarcmsmasg, -w flag means to wait for a switch to be plugged in
this injects the biskeydump payload and the BOOT:0x0 has the output writted to the commandline. This comes out in some sort of 16bit encoding which causes null bytes between
each character when piped into a file
#>

(Get-Content "prod.keys") -replace "`0", "" | findstr : | Set-Content "prod.keys"
<#
This reads the output file, removes the nullbytes and re-writes it after finding the relevent key lines
#>

echo "Key dump complete, please restart the Switch into RCM mode"

Tools\TegraRcmSmash.exe -w Tools\memloader.bin -r --dataini=Tools\ums_emmc.ini

<#
this injects the memloader which mounts the memory. the -r flag allows for pushing files to the sd card, the --dataini is put on the sd card
and contains the settings to mount the NAND
#>
echo "Mounting NAND. Please wait..."

Start-Sleep -Seconds 5
$drive = wmic diskdrive where "caption='Linux UMS disk 0 USB Device'" get name | findstr /c:PHYSICALDRIVE

echo "Starting NAND dump"


<# 
The above command needs to get the Physical address e.g \\.\PHYSICALDRIVE2 of the switch to feed to NxNandManager.exe,
After changing from cmd to powershell (to use Get-Content to fix the quirky null-byte output of prod.keys) this no longer works and needs fixing 
#>

Tools\NxNandManager\NxNandManager.exe -i $drive -o rawnand.bin

<# 
This initiates the NAND dump in the command line from the mounted drive and writes it out
#>