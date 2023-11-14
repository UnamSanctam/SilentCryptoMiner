### 3.4.0 (14-11-2023)
* Changed administrator "Startup" installation procedure from using the Task Scheduler to instead install as a Service
* Changed the Administrator "Startup" installation from installing into "Program Files" to instead install into "ProgramData"
* Removed the "Run as System" option due to Services always running as System
* Added MSRT removal to the "Add Defender Exclusions" feature
* Changed the C++ compiler to one with less detections and better features
* Improved external compiler starting procedure to bypass compiler bugs when the build path contains spaces or unicode characters
* Modified the compilation process to incorporate "strip" for the removal of all unnecessary symbols and relocation data
* Adjusted compiler optimization level to mitigate some antivirus detections
* Enabled LTO during compilation to remove a lot of compiler caused detections from unused sections
* Changed the compiler from using temporary files to instead use pipes in order to work better with some irregular environments
* Changed the compilation procedure to add a randomized creation date and last write date to the built miner files
* Reverted miner builder .NET Framework version back to .NET 4.5 from .NET 4.8 for better compatibility
* Changed the miner injection technique to both reduce complexity and antivirus detections
* Optimized the process creation code
* Remade miner injection loop code and watchdog mutex check loop code to bypass a new targeted Windows Defender detection
* Greatly improved the SysWhispersU syscall generator
* Switched over from static syscalls to randomized dynamic syscalls
* Changed the "Run as Administrator" feature to elevate programmatically instead of through a manifest file to avoid manifest caused detections
* Added obfuscation to all constants and literals
* Added base64 encoding to embedded files in order to bypass detections caused by high entropy data
* Changed the embedded resource format from hex to decimal in order to reduce memory usage and time during compilation
* Changed the default "Startup" tabs "Entry Name" and "File Name" to a randomized string due to Windows Defender targeting the current default names
* Added new "Randomize" button next to the "Startup" tabs "Entry Name" and "File Name" options to allow for fast randomization
* Added new "Advanced Option" that allows automatic UPX packing of the embedded miner resource files
* Changed the "Disable Windows Update" and "Disable Sleep" functions to directly call the programs instead of calling them through a command line
* Changed default "Inject Into" program to conhost.exe instead of explorer.exe due to explorer.exe now triggering detections when running under System
* Added ".exe" extension exclusion to "Add Defender Exclusions" feature in order to potentially prevent some future general memory detections
* Removed XMR "GPU Mining" option due to problems with CUDA and it being worse than the already existing dedicated GPU miner
* Removed XMR "CPU Mining" option due to it having no reason to exist now that the "GPU Mining" option is gone
* Rewrote XOR cipher function to bypass XOR obfuscation detection
* Remade the "Block Websites" feature code to bypass some detections caused by looping
* Greatly improved the overall code to reduce wasteful calls, handles and possible code signatures
* Changed "Start Delay" to only apply before installation in order to avoid timeouts
* Updated the uninstaller to properly remove all files
* Updated the miners
### 3.3.1 (04/09/2023)
* Added OpenCL ICD loader statically into the GPU miner because some systems local loaders do not seem to work
* Added automatic CPU mining core restart when a prolonged period of zero hashrate is detected
* Fixed administrator "Startup" trigger to be "on login" when "Run as System" is disabled
* Reduced some antivirus detections by modifying the miner compilation command
* Changed some miner builder compiler commands to be absolute instead of relative
* Added "Assembly" tab "Version" number sanitization
* Fixed unnecessary log warning during compilation
* Removed many old unused debug strings inside the miners
### 3.3.0 (24/08/2023)
* Added the KawPow (kawpow) algorithm directly into the GPU miner
* Added new FiroPow (firopow) algorithm
* Added new ProgPow (progpow) algorithm
* Added new ProgPowZ (progpowz) algorithm
* Added new EvrProgPow (evrprogpow) algorithm
* Implemented KawPow, FiroPow, EvrProgPow, ProgPow and ProgPowZ using only OpenCL for both Nvidia and AMD to bypass large CUDA NVRTC library requirement
* Rewrote most of the GPU miner to add support for multiple algorithm families and to greatly improve stability and reliability
* Added Sero-Proxy protocol to be able to mine Sero (ProgPow)
* Removed KawPow (kawpow) algorithm from the XMR miner and also the large CUDA NVRTC library to make sure no one accidentally uses it
* Re-added the Panthera (rx/xla) algorithm
* Added Zephyr coin (rx/0) solo mining support
* Moved the XMR miner "GPU Mining" option into the "Advanced" tab to discourage unprofitable XMR GPU mining
* Moved the "Use Rootkit" option into the "Advanced Options" for better clarity regarding its complexity
* Changed Task Scheduler Task creation from Powershell to only using the command line with a temporary XML file
* Changed MSR driver path from using a static library path to a dynamically generated path
* Modified embedded file encryption and decryption to reduce heuristic detections
* Changed the code compiler build to different one to greatly reduce the compiler-caused antivirus detections
* Improved the external compiler execution commands by better forcing absolute paths in commands
* Added a mutex into the miner installer/injector to make it checkable by the watchdog
* Reduced the watchdog checking interval for better persistance
* Removed unused helper functions
* Rewrote uninstallers miner killer function to work with Process IDs above the ushort limit
* Changed unicode string initialization from a macro to a function to reduce the final code size
* Changed string formatting from using the built-in Windows API to instead use a much smaller custom function
* Moved web panel reporting to happen before CPU idle usage change in order to help make the hashrate look less confusing
* Improved RandomX database regeneration speed when leaving "Stealth" on pools with infrequent new jobs
* Fixed weird default "Stealth on Fullscreen" configuration value when "Run as System" was disabled
* Fixed possible null terminator string length counting problem inside the GPU checking function
* Reduced unnecessary recursive directory creation function stack size
* Changed miners execution state to no longer always semi-block sleep mode on some computers
* Restructured the algorithm selection list to be easier to use
* Added semi-CLI functionality for building miners through the command line
* Updated the rootkit to a new version
### 3.2.0 (01/04/2023)
* Changed miner settings from being passed through the command line to instead be passed directly through the PEB
* Changed XMR miner to clear RAM during "Stealth" when possible
* Changed PEB calls to be more obfuscated due to new detections
* Changed miner to read the current executable path for installation directly from the PEB instead of a Windows API call
* Changed miner and watchdog to read the environmental variables directly by traversing the PEB
* Included rootkit directly inside the miner instead of using the rootkit installer to avoid the new AMSI detections and for more flexibility
* Changed rootkit to now run outside of the "Startup" installation flow to allow for it to run when "Startup" is disabled
* Moved "Install Rootkit" out from "Advanced Options" and renamed it to "Use Rootkit (Hide Miner)" since the rootkit should now be stable
* Updated compiler command options to reduce detections
* Added system call registry access functions to allow registry manipulation without using the Windows API or CMD
* Changed GPU checking to directly read the registry instead of using a WMI command with a file buffer
* Added signature cloning tab where you can clone the digital certificate of another program into the miner
* Moved administrator checks from powershell directly into the C++ code
* Added Task Scheduler "Startup" entry checking into the Watchdog
* Merged obfuscate.h library and obfuscatew.h library into a custom-made unified version called obfuscateu.h
* Added a custom-made SysWhispersU direct system call generator and removed the previous SysWhispers2
* Modified SysWhispersU and obfuscateu.h to use different encryptions in order to avoid XOR detections
* Added simple obfuscation to well-known SysWhispers constants and offsets to avoid static detections
* Readded explorer.exe as injection option
* Made explorer.exe the default injection option again
* Updated uninstaller to instead find the watchdog and miner processes by enumerating system mutex handles to find the owner process
* Added "Disable Windows Update" rollback into the uninstaller to allow the uninstaller to fix Windows Update during uninstallation
* Updated checker to instead check if the mutex is active to ascertain whether the miner and watchdog is running or not
* Merged many C++ files together to be able to store them unzipped in the project in order to make all code changes directly visible in commits
* Optimized and shortened many functions such as the previously verbose process creation function
* Increased delete pending injection temporary file name length to further decrease collision chance
* Fixed possible parent spoofing failure if required buffer size changes between system calls
* Change installation to call reg.exe and schtasks.exe directly when possible instead of through cmd.exe
* Fixed "Startup" installation bug on some systems when "Entry Name" contained a space
* Fixed support for Unicode characters inside the "Assembly" settings
* Updated both miners
* Added Portuguese (Brazil) translation (MatheusOliveira-dev)
### 3.1.0 (31/10/2022)
* Changed process creation from undocumented API calls to direct system calls
* Added process parent spoofing with token impersonation when creating processes
* Created custom process parameter creation to avoid API calls
* Added system call process enumeration for parent spoofing
* Updated SysWhispers2 with custom process creation definitions and more
* Modified SysWhispers2 assembler instructions to bypass new detection
* Changed all indirect API calls to direct system calls
* Changed compiler binaries to reduce some compiler caused detections
* Fixed known XMR "GPU Mining" compilation error with new compiler
* Fixed XMR GPU library location checking on some systems
* Changed GPU memory checking from CUDA API to NVML for much better accuracy
* Updated ethminer CUDA and OpenCL mining implementations
* Updated ethash, etchash and ubqhash algorithm implementation
* Added improved CUDA and OpenCL automatic restart on error or crash
* Improved GPU limit sleep time accuracy for powerful GPU cards
* Removed ETH from the preset list due to the ETH merge from PoW to PoS
* Added EthereumPoW (ETHW) fork of ETH to the preset list
* Rewrote website blocking to avoid using string to reduce dependencies
* Updated rootkit and fixed some rootkit bugs
* Fixed many miscellaneous bugs
* Updated xmrig
### 3.0.2 (09/09/2022)
* Added GPU check support for some Radeon RX GPUs
* Added more API function bypasses for lower possible future detections
* Changed compiler paths from relative to absolute paths
### 3.0.1 (07/09/2022)
* Fixed GPU checking when running as the System user
* Future-proofed some possible future detections
### 3.0.0 (07/09/2022)
* Rewrote entire miner and watchdog in C++ to replace the C# miner and watchdog
* Rewrote much of the builder for the rewritten miner and watchdog
* Added custom C++ compiler package
* Added custom compiled version of SysWhispers2 to randomize syscalls seed on every build
* Changed default injection target to conhost.exe
* Removed injection target "explorer.exe" due to new protections and inconvenience
* Added new injection target "dwm.exe"
* Removed now unnecessary options "Shellcode Loader", "In-memory watchdog" and "Do built-in obfuscations" because of the rewrite
* Removed now unnecessary DLL modules because of direct implementations
* Temporarily removed the "DEBUG" and "Overwrite old miners" options
* Updated both miners
* Added Spanish translation (Xeneht)
* Added Russian translation (BITIW)
### 2.6.1 (19/08/2022)
* Fixed mysterious reported ETH stratum disconnection
* Further improved ETH miner web panel status reporting from feedback
* Reduced minimum minor CUDA version for more driver compatibility
* Reduced ETH VRAM CUDA overhead slightly
* Reduced critical process protection delay
* Fixed missing builder admin shield images
### 2.6.0 (18/08/2022)
* Bypassed new Windows Defender exclusion detection and removal
* Added new improved process hollowing module ProcessInject which replaces the old process hollowing
* Added new "Critical Processes (BSoD)" option to mark the miners and watchdog as critical processes, thus causing a BSoD when killed
* Added new in-memory native DLL loader for the new modules, ProcessInject and ProcessProtect
* Greatly improved dynamic DAG/VRAM management, including better regeneration when enough VRAM becomes available to mine
* Changed startup flow to be more dynamic and persistent
* Improved the watchdogs persistence
* Greatly improved ETH miners web panel status reporting logic
* Improved ETH miners failover connection logic and default timing parameters
* Removed AstroBWT algorithms due to constant forking and instabilities
* Updated XMR miner
* Added Polish translation (Werlrlivx)
### 2.5.0 (06/07/2022)
* Added language localizer to allow translations of all controls through XML
* Added Swedish translation
* Changed "Save Path" to show "Program Files" for clarity when "Run as System" and "Run as Administrator" are both enabled
* Moved AMSI bypass from the RunPE module into the miner to bypass Assembly.Load detections
* Obfuscated all remaining strings inside all files
* Remade manifest to reduce detections
* Added new advanced option to disable built-in obfuscations
* Updated rootkit to reduce detections and improve compatibility and reliability
* Improved process hollowing implementation
### 2.4.1 (06/06/2022)
* Removed Panthera (Panthera) algorithm due to reported collateral issues
* Updated ETH miner CUDA and OpenCL implementations
* Added ETH miner OpenCL fallback for Nvidia cards if CUDA is unavailable
* Fixed connections to some ghostrider pools
* Fixed ETH first web panel configuration and first "Remote Configuration" pool switching
* Fixed Clover platform support
* Fixed non-intended administrator permission request during normal user first installation start
* Fixed brief powershell window popup on administrator installation startups with "Run as System" disabled
### 2.4.0 (29/05/2022)
* Added new Ubqhash (ubqhash) algorithm
* Added new CryptoNight-GPU (cn/gpu) algorithm
* Added new Panthera (panthera) algorithm
* Added new AstroBWT V2 (astrobwt/v2) algorithm
* Added new option "Stealth on Fullscreen" to pause the miner when Windows reports a fullscreen program to be open on the user running the miner
* Added executable name to the web panel "Active Window" reporting
* Added executable name reporting of the found "Stealth Targets" during "Stealth" to the web panel
* Added UTF8 encoding to GPU and CPU name web panel reporting
* Added C# shellcode injector for in-memory watchdog injection without an intermediary "Shellcode Loader"
* Changed Task Scheduler task creation from schtasks command to powershell to greatly increase customizability of the task
* Changed Task Scheduler task conditions and settings to the most optimal for the miner
* Changed Task Scheduler task to start at system startup instead of any user login when "Run as System" is enabled
* Fixed Task Scheduler task on some systems when install path contains spaces
* Replaced many commands with obfuscated powershell versions
* Reworked miner installation code and methods
* Reworked miner checking loops to ensure correct web panel status reporting and better performance
* Added support for reporting to the web panel when running at least two miners of the same miner type
* Improved watchdog miner restoration
* Updated the rootkit
### 2.3.2 (30/04/2022)
* Changed miner to install into Program Files if installed with "Run as System" enabled
* Changed miner to instead start from the Task Scheduler instead of CMD immediately after install if running as administrator
* Changed Icon preview to reload after loading a save
* Reworked "Remote Configuration" and web panel API calls for better performance, flexibility and less overhead
* Changed miner to immediately start reporting to the web panel on start
* Added new "Starting" miner status when first reporting to the web panel
* Added new miner version reporting to the web panel
* Added new currently active window reporting to the web panel
* Added new miner run time reporting to the web panel
* Inverted some advanced options for better clarity
### v2.3.1 (21/04/2022)
* Changed ETH miner to force desired CUDA settings, can increase hashrate on newer drivers/GPUs
* Changed ETH miner to not mine on integrated Intel GPUs, meaning CPUs with a GPU in them since they are not profitable and can cause lag
* Reworked manifest system to reduce overall detections
* Reduced C# detections greatly, especially helpful for those with "Shellcode Loader" disabled
* Changed "Entry Name" check to reallow backslashes for Task Scheduler subsections
* Improved "Disable Windows Update" function with better persistence and effectiveness
* Added advanced option to disable the miner from running after install so that it will only run on startup
### v2.3.0 (09/04/2022)
* Added option to disable Windows Update which stops updates from being found and installed
* Changed Watchdog to now run only in memory with no file dropped
* Added new Advanced Options form to make space for more options
* Added advanced option to use old Watchdog behaviour and start as a dropped file instead of only in memory
* Added advanced option to not overwrite old installed miners if desired
* Changed HTTP library to always follow redirects
* Decreased miner stealth and idle check loop timer for faster checks
* Moved process hollowing code back into DLL
* Added custom user level manifest
* Reduced some antivirus detections, mainly in C# code
* Cleaned up builder and miner code
* Fixed uninstaller
* Removed duplicate disable sleep command
* Updated miner
### v2.2.1 (05/04/2022)
* Added morphing to Windows Defender exclusion command to avoid static detection
* Added option to run/install the miner as System instead of always doing so by default
* Changed rootkit target program from nslookup.exe to dialer.exe and modified rootkit workflow
* Fixed XMR difficulty negotiation
* Fixed XMR worker name variable replacement
* Fixed XMR CUDA library locator for unicode characters
* Fixed missing builder events
### v2.2.0 (01/04/2022)
* Added custom system-wide idle detection that replaces the previous dedicated Windows API idle detection, this allows the miner to be run as "System"
* Changed miner to be installed with the "System" user when run as administrator, which means that it will now run when the computer is started with any user
* Added field to customize the entry name displayed in the startup registry and Task Scheduler
* Added option to automatically delete the original miner file after installation finishes
* Added option to disable sleep and hibernation on the computer
* Added option to block websites/domains from being able to be accessed by using the hosts file
* Fixed computer name and username convertions when containing non-ASCII characters
* Changed default library and installation locations to avoid path access restrictions by some programs
* Fixed XMR miner GPU CUDA libraries
* Fixed missing Watchdog Loader obfuscation step when using "Pause for Obfuscation"
* Improved GhostRider algorithm implementation
* Changed ETH miner idle sleeping 
* Fixed minor builder bugs
* Cleaned up form elements
* Added icon file error checking
* Updated compilers
* Updated miners
### v2.1.0 (09/01/2022)
* Added Ghost Rider algorithm, mainly used for the coin Raptoreum
* Added JSON generator inside builder for easier "Remote Configuration" and web panel configuration creation
* Added rootkit helper signatures to relevant files to ensure that files and processes are not hidden from the miner processes
* Added new "Out of free VRAM" status for the web panel if no GPU has enough current free VRAM to mine the selected coin
* Added "remote-config" and "api-endpoint" configuration options for the "Remote Configuration" and web panel configurations
* Changed save/load form serialization to also save checkbox and toggle text states
* Changed default "Startup" "Filename" due to certain anticheats blocking default "Startup" folder access
* Changed "Shellcode Loader" code and overall flow
* Improved rootkit stability and stealth
* Cleaned up messy and unclear form control names, breaks old save compatibility
### v2.0.1 (09/11/2021)
* Removed "Hide File" option due to it restricting the file from being written to, thus enabling it to cause unwanted behaviour and bugs
* Fixed possible bug where the random encryption keys could be generated with illegal characters
* Fixed builder bug where it didn't clear the miner set for the Watchdog between builds
* Fixed Monero icon
### v2.0.0 (08/11/2021)
* Initial release