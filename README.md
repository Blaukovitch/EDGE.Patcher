![progress](http://www.yarntomato.com/percentbarmaker/button.php?barPosition=77&leftFill=%23FF0000 "progress") 
# EDGE.Patcher™
Official tool for binary patching (assembly bithack &amp; string replace) propietary Microsoft EDGE (msedge.exe) &amp; Google Chrome (chrome.exe) browsers.

# © NOT MY!
VERY Big thanks for:  **-Q (QuQuRoon)**  

 Fixes/addings/publishing by: *ELF (386 Team)*  

 ## Struct
**Language: C#**
| Filename                  | Description                                                  |
| ------------------------- |:------------------------------------------------------------:|
| `BinaryFileSearch.cs`     | search req patterns in binary PE COFF (.exe/.dll) streams    |
| `Helpers.cs`              | string/path/buffer ops                                       |
| `Models.cs`               | internal classes and enums                                   |
| `PeHeaderReader.cs`       | PE COFF format descriptors                                   |
| `Program.cs`              | MAIN entryside, PRIMARY operations lists                     |

## How to use
* Windows **10/11**. Copy `C:\Program Files\Google\Chrome\Application\` || `C:\Program Files\Microsoft\Edge\Application` folder [ver. 110 and above](https://support.google.com/chrome/thread/185534985/sunsetting-support-for-windows-7-8-8-1-and-windows-server-2012-and-2012-r2-in-early-2023?hl=en) in to Windows **7** machine (ex: `C:\Temp\Application`)   
* Windows **7** machine. Run `Edge.Patcher.exe` with next args:  
* * Path to local copy the *Application* folder (ex: `C:\Temp\Application`);    
* * One of keys **-all** (path all known targets) or **-ntp** (path only NTP server strings);    
* * If NOT need check [API-MS](https://github.com/Blaukovitch/API-MS-WIN_XP/) presents, you can add **-wo** key;  
* Windows **7** machine. Wait for the crack operation to complete;  
* Windows **7** machine. Copy API-MS libs (x64/x86) in to ROOT and VER directories;  
* Windows **7** machine. Verify patched variant via run `chrome.exe`/`msedge.exe`. For **x86** vers may be need *-no-sandbox* or manual bithack in to [OllyDbg](https://www.ollydbg.de/)/(x32dbg)[https://x64dbg.com/];
* Windows **7** machine. Remember that **x64** of browsers versions affected VirtualAlloc (MEM_RESERVED) memory HUGE bug;
* Windows **7** machine. Swap ver. 109  `C:\Program Files\Google\Chrome\Application\` || `C:\Program Files\Microsoft\Edge\Application` to you patched version from ex: `C:\Temp\Application`
* Piracy WIN! ^)

> [!CAUTION]
> ❌ Be advice: this repository may be disabled!

### Abilites
> Redirect PE COFF IMPORT/Delay table to API-MS libs;  
> Patch binary assembly code;  
> Clear PE COFF certificate area;  

### About 
```
-Q (QuQuRoon), 2024  
386 Team, 2024  
CRACKLAB, 2024
```

#### 	> Disclaimer:
	---------------------------------------------------------------------------------------------------------------------------------------
	When used a released compiled NET. PE EXE, this code provide DMCA copyright infringement against Microsoft and Google, but nobody cares. 
	---------------------------------------------------------------------------------------------------------------------------------------
