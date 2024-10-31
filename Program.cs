﻿/*
 ORIGINAL CODE WRITTEN BY:
 -Q (QuQuRoon)
 
 FIXES/ADDINGS/PUBLISHING BY:
 ELF (386 Team)

 MicroSoft EDGE / Google Chrome
 ******************************
 x64: pass!
 x86: '-no-sandbox' needed

	CRACKLAB
	https://www.reddit.com/r/windows7/comments/18e52q3/behold_google_chrome_v120_running_on_windows_7/
	https://cracklab.team/index.php?threads/1037/page-8#post-14319
	https://xakep.ru/2023/08/10/chrome-for-windows-7/
	https://habr.com/ru/articles/752692/
	https://habr.com/ru/articles/789120/
	https://habr.com/ru/articles/817561/
	https://cracklab.team/PAunlock/
	2023-2024


	
	> Disclaimer:
	---------------------------------------------------------------------------------------------------------------------------------------
	When used a released compiled NET. PE EXE, this code provide DMCA copyright infringement against Microsoft and Google, but nobody cares. 
	Piracy WIN!
	---------------------------------------------------------------------------------------------------------------------------------------
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Edge.Patcher
{
	class Program
	{
		static int Main(string[] args)
		{
			string rootFolder = args.FirstOrDefault() ?? Directory.GetCurrentDirectory();
			if (!rootFolder.EndsWith(Path.DirectorySeparatorChar.ToString()))
			{
				rootFolder += Path.DirectorySeparatorChar;
			}

			var updateType = UpdateType.None;
			var updateTypeArg = args.Skip(1).FirstOrDefault();
			bool without_scan_apims_libs = false;
			if (string.Equals(updateTypeArg, "-all", StringComparison.OrdinalIgnoreCase))
			{
				updateType = UpdateType.All;
			}
			else if (string.Equals(updateTypeArg, "-ntp", StringComparison.OrdinalIgnoreCase))
			{
				updateType = UpdateType.NtpOnly;
			}
			else if (string.Equals(updateTypeArg, "-ref", StringComparison.OrdinalIgnoreCase))
			{
				updateType = UpdateType.References;
			}
			
			if (string.Equals(updateTypeArg, "-wo", StringComparison.OrdinalIgnoreCase))
				without_scan_apims_libs = true;

			try
			{
				ScanAndPatch(rootFolder, updateType);
			}
			catch (Exception ex)
			{
				var hrCode = Marshal.GetHRForException(ex);
				if (hrCode != 0)
				{
					Console.WriteLine("HResult - 0x{0:x}", hrCode);
				}
				Console.WriteLine(ex.ToString());
				return hrCode == 0 ? 1 : hrCode;
			}

			//(ELF) add
			if (!without_scan_apims_libs)
            {
                Verify_APIMSLibs_status(rootFolder, extensions);
            }
			return 0;
		}

		private static void ScanAndPatch(string rootFolder, UpdateType updateType)
		{
			Console.WriteLine("Scanning {0}", rootFolder);
			var extensions = new[] { ".exe", ".dll" };

			foreach (var file in files)
			{
				var actualFiles = Directory.GetFiles(rootFolder, file.FileName, SearchOption.AllDirectories)
					.Where(x => extensions.Contains(Path.GetExtension(x)));
				foreach (var actualFile in actualFiles)
				{
					Console.WriteLine("Found file {0}", rootFolder.GetRelativePath(actualFile));
					var pe = new PeHeaderReader(actualFile);

					if ((updateType & UpdateType.References) == UpdateType.References || updateType == UpdateType.None)
					{
						foreach (var import in pe.ImportName2FileOffset.Where(x => file.Imports.ContainsFile(x.Key)))
						{
							Console.WriteLine("  Import - {0} at 0x{1:X}", import.Key, import.Value);
							if (file.Imports.ContainsKey(import.Key))
							{
								PatchFile(updateType, actualFile, import.Value, Encoding.ASCII.GetBytes(file.Imports[import.Key]));
							}
						}

						foreach (var import in pe.DelayLoadName2FileOffset.Where(x => file.DelayImports.ContainsFile(x.Key)))
						{
							Console.WriteLine("  Delay Import - {0} at 0x{1:X}", import.Key, import.Value);
							if (file.DelayImports.ContainsKey(import.Key))
							{
								PatchFile(updateType, actualFile, import.Value, Encoding.ASCII.GetBytes(file.DelayImports[import.Key]));
							}
						}

						long fileOffset;
						if (file.NullifyCertificateTable)
						{
							fileOffset = pe.OptionalHeaderField2FileOffset("CertificateTable");
							Console.WriteLine("  NullifyCertificateTable - at 0x{0:X}", fileOffset);
							PatchFile(updateType, actualFile, fileOffset, new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 });
						}

						fileOffset = pe.OptionalHeaderField2FileOffset("MajorOperatingSystemVersion");
						Console.WriteLine("  OS Version - at 0x{0:x}", fileOffset);
						PatchFile(updateType, actualFile, fileOffset, new byte[] { 05, 00, 02, 00 });

						fileOffset = pe.OptionalHeaderField2FileOffset("MajorSubsystemVersion");
						Console.WriteLine("  Subsystem Version - at 0x{0:x}", fileOffset);
						PatchFile(updateType, actualFile, fileOffset, new byte[] { 05, 00, 02, 00 });
					}

					var bfs = new BinaryFileSearch(actualFile);
					var binaries = updateType == UpdateType.None 
						? file.Binary
						: file.Binary.Where(x => (x.Value.UpdateType & updateType) != UpdateType.None).ToDictionary(x => x.Key, x => x.Value);

					var archType = pe.Is32BitHeader ? ArchTypeE.x86 : ArchTypeE.x64;
					binaries = binaries
						.Where(x => x.Value.ArchType == ArchTypeE.Both || x.Value.ArchType == archType)
						.ToDictionary(x => x.Key, x => x.Value);

					var byteReferences = bfs.FindReferences(binaries);
					var padding = byteReferences.Any() ? byteReferences.Max(x => x.Key.Length) : 0;
					foreach (var import in byteReferences)
					{
						Console.WriteLine("  Bytes - {0} at 0x{1:X}", import.Key.PadRight(padding), import.Value);
						if (file.Binary.ContainsKey(import.Key))
						{
							PatchFile(updateType, actualFile, import.Value, file.Binary[import.Key].Value);
						}
					}
					Console.WriteLine("  Found {0} out of {1} binary references", byteReferences.Count, binaries.Count);

					Console.WriteLine();
				}
			}
		}

		private static void PatchFile(UpdateType updateType, string filePath, long fileOffset, byte[] replacement)
		{
			if (updateType == UpdateType.None)
			{
				return;
			}

			int updatedBytes = 0;
			using (FileStream stream = new FileStream(filePath, FileMode.Open, FileAccess.Write))
			{
				for (int i = 0; i < replacement.Length; i++)
				{
					stream.Seek(fileOffset + i, SeekOrigin.Begin);
					if (replacement[i] != 0xFF)
					{
						stream.WriteByte(replacement[i]);
						updatedBytes++;
					}
				}
				stream.Flush();
			}
			Console.WriteLine("	 Updated {0} of {1} bytes at 0x{2:X}", updatedBytes, replacement.Length, fileOffset);
		}

		private static readonly ReplaceItem[] files = new ReplaceItem[]
		{ 
			new ReplaceItem 
			{
				FileName = "msedge_proxy.exe",
				NullifyCertificateTable = true,
				Imports = new Dictionary<string,string> { { "kernel32.dll", "KERNEL64.dll" } },
				DelayImports = new Dictionary<string,string> { { "userenv.dll", "USERENX.dll" } },
				Binary = new Dictionary<string, BinaryDescriptor> 
				{
					{ "bcrypt", new BinaryDescriptor {
					    Key = Encoding.Unicode.GetBytes("bcryptprimitives"),
					    Value = Encoding.Unicode.GetBytes("xcryptprimitives") }
					},
					{ "RtlGetDeviceFamilyInfoEnum", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte[] {
					        0x56, 0x57, 0x48, 0x83, 0xec, 0x38, 0x48, 0x8b, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x31, 0xe0, 0x48,
					        0x89, 0x44, 0x24, 0x30, 0xc7, 0x44, 0x24, 0x2c, 0xff, 0xff, 0xff, 0xff, 0x48, 0x8d, 0x0d, 0xFF, 0xFF,
					        0xFF, 0x00, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8d, 0x15, 0xff, 0xff, 0xff, 0x00, 0x48, 0x89,
					        0xc1, 0xff, 0x15, 0xff, 0xff, 0xff, 0x00},
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90, 0x48, 0x8b}
					} },
					// 55               push        ebp
					// 89E5             mov         ebp,esp
					// 56               push        esi
					// 83EC08           sub         esp,8
					// A140004D00       mov         eax,[0004D0040]
					// 31E8             xor         eax,ebp
					// 8945F8           mov         [ebp][-8],eax
					// C745F4FFFFFFFF   mov         d,[ebp][-00C],-1
					// 683C0E4C00       push        0004C0E3C ;'ntdll.dll'
					// FF15E0B94C00     call        GetModuleHandleW
					// 68103F4C00       push        0004C3F10 ;'RtlGetDeviceFamilyInfoEnum'
					// 50               push        eax
					// FF15ECB94C00     call        GetProcAddress
					// 85C0             test        eax,eax
					// 742D             jz         .00045CFD0
					{ "RtlGetDeviceFamilyInfoEnum (x86)", new BinaryDescriptor {
					    ArchType = ArchTypeE.x86,
					    Key = new byte[] {
					        0x55, 0x89, 0xe5, 0x56, 0x83, 0xec, 0x08, 0xa1, 0xFF, 0xFF, 0xFF, 0xFF, 0x31, 0xe8, 0x89, 0x45, 0xf8,
					        0xc7, 0x45, 0xf4, 0xff, 0xff, 0xff, 0xff, 0x68, 0xff, 0xff, 0xff, 0xFF, 0xff, 0x15 },
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x56, 0x83, 0xec, 0x08, 0xa1}
					} }
				}
			},
			new ReplaceItem
			{
				FileName = "msedge.exe",
				NullifyCertificateTable = true,
				Imports = new Dictionary<string,string> { { "kernel32.dll", "KERNEL64.dll" } },
				DelayImports = new Dictionary<string,string> { { "userenv.dll", "USERENX.dll" } },
				Binary = new Dictionary<string, BinaryDescriptor>
				{
					{ "bcrypt", new BinaryDescriptor {
					    Key = Encoding.Unicode.GetBytes("bcryptprimitives"),
					    Value = Encoding.Unicode.GetBytes("xcryptprimitives") }
					},
					{ "RtlGetDeviceFamilyInfoEnum", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte [] {
					        0x56, 0x48, 0x83, 0xec, 0x30, 0x48, 0x8b, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x31, 0xE0, 0x48, 0x89,
					        0x44, 0x24, 0x28, 0xC7, 0x44, 0x24, 0x24, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8D, 0x0D, 0xFF, 0xFF, 0xFF,
					        0x00, 0xFF, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8D, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xC1},
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x90, 0x90, 0x48, 0x8b, 0x05} }
					},
					{ "RtlGetDeviceFamilyInfoEnum (x86)", new BinaryDescriptor {
					    ArchType = ArchTypeE.x86,
					    Key = new byte[] {
					        0x55, 0x89, 0xe5, 0x56, 0x83, 0xec, 0x08, 0xa1, 0xFF, 0xFF, 0xFF, 0xFF, 0x31, 0xe8, 0x89, 0x45, 0xf8,
					        0xc7, 0x45, 0xf4, 0xff, 0xff, 0xff, 0xff, 0x68, 0xff, 0xff, 0xff, 0xFF, 0xff, 0x15 },
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x56, 0x83, 0xec, 0x08, 0xa1}}
					},
					{ "TerminateProcess", new BinaryDescriptor {
						ArchType = ArchTypeE.x64,
						Key = new byte [] {
							0x75, 0x14, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xc1, 0xba, 0x62, 0x1b, 0x00, 0x00, 0xff,
							0x15 },
						Value = new byte[] {
							0xeb, 0x14, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xc1, 0xba, 0x62, 0x1b, 0x00, 0x00, 0xff,
							0x15} }
					},
					{ "TerminateProcess (alt)", new BinaryDescriptor {
						ArchType = ArchTypeE.x64,
						Key = new byte [] {
							0x75, 0x31, 0xe8, 0xff, 0xff, 0xff, 0xff, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xc1, 0xba,
							0x62, 0x1b, 0x00, 0x00, 0xff, 0x15},
						Value = new byte[] {
							0xeb, 0x31, 0xe8, 0xff, 0xff, 0xff, 0xff, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xc1, 0xba,
							0x62, 0x1b, 0x00, 0x00, 0xff, 0x15} }
					},
					{ "TerminateProcess (alt 2)", new BinaryDescriptor {
						ArchType = ArchTypeE.x64,
						Key = new byte [] {
							0x84, 0xc0, 0x74, 0x24, 0x40, 0x8a, 0x69, 0x05, 0xe8, 0xff, 0xff, 0xFF, 0xFF, 0xeb, 0x32},
						Value = new byte[] {
							0x90, 0x90, 0x90, 0x90, 0x40, 0x8a, 0x69, 0x05, 0xe8, 0xff, 0xff, 0xFF, 0xFF, 0xeb, 0x32} }
					},
					{ "TerminateProcess (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] {
							0x84, 0xc0, 0x74, 0x1b, 0x8a, 0x85, 0xff, 0xff, 0xff, 0xff, 0x88, 0x85, 0xFF, 0xff, 0xff, 0xff, 0x89,
							0xd9, 0xe8},
						Value = new byte[] {
							0x90, 0x90, 0x90, 0x90, 0x8a, 0x85, 0xff, 0xff, 0xff, 0xff, 0x88, 0x85, 0xFF, 0xff, 0xff, 0xff, 0x89,
							0xd9, 0xe8} }
					},
					// 55             push        ebp
					// 89E5           mov         ebp,esp
					// 53             push        ebx
					// 57             push        edi
					// 56             push        esi
					// 83EC28         sub         esp,028            --> sub esp,058
					// 89CB           mov         ebx,ecx
					// 8B7D1C         mov         edi,[ebp][01C]
					// 0F106508       movups      xmm4,[ebp][8]
					// A140706300     mov         eax,[000637040]
					{ "ReadProcessMemory (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] { 0x55, 0x89, 0xe5, 0x53, 0x57, 0x56, 0x83, 0xec, 0x28, 0x89, 0xcb, 0x8b, 0x7d, 0x1c},
						Value = new byte[] {0x55, 0x89, 0xe5, 0x53, 0x57, 0x56, 0x83, 0xec, 0x58, 0x89, 0xcb, 0x8b, 0x7d, 0x1c} }
					},
					// 660F76C0                       pcmpeqd     xmm0,xmm0
					// 8D45D8                         lea         eax,[ebp][-028]	--> lea eax,[ebp][-058]
					// F30F7F00                       movdqu      [eax],xmm0
					{ "ReadProcessMemory2 (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] {0x66, 0x0f, 0x76, 0xc0, 0x8d, 0x45, 0xd8, 0xf3, 0x0f, 0x7f, 0x00},
						Value = new byte[] {0x66, 0x0f, 0x76, 0xc0, 0x8d, 0x45, 0xa8, 0xf3, 0x0f, 0x7f, 0x00} }
					},
					// 8D4DEC         lea         ecx,[ebp][-014]
					// C701FFFFFFFF   mov         d,[ecx],-1
					// 51             push        ecx
					// 6A10           push        010				--> push 020
					// 50             push        eax
					// FF7304         push        d,[ebx][4]
					// FF7310         push        d,[ebx][010]
					// FF15B4306300   call        ReadProcessMemory
					// 85C0           test        eax,eax
					{ "ReadProcessMemory3 (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] {
							0xc7, 0x01, 0xff, 0xff, 0xff, 0xff, 0x51, 0x6a, 0x10, 0x50, 0xff, 0x73, 0x04, 0xff, 0x73, 0x10, 0xff, 
							0x15, 0xff, 0xff, 0xff, 0xff, 0x85, 0xc0},
						Value = new byte[] {
							0xc7, 0x01, 0xff, 0xff, 0xff, 0xff, 0x51, 0x6a, 0x20, 0x50, 0xff, 0x73, 0x04, 0xff, 0x73, 0x10, 0xff,
							0x15, 0xff, 0xff, 0xff, 0xff, 0x85, 0xc0} }
					},
					// 0F841A010000   jz         .000465646
					// 837DEC10       cmp         d,[ebp][-014],010	--> cmp d,[ebp][-014],020
					// 0F8510010000   jnz        .000465646
					// 807DD8E9       cmp         b,[ebp][-028],0E9 --> cmp b,[ebp][-058],0E9
					// 8B7D1C         mov         edi,[ebp][01C]
					// 7517           jnz        .000465556 
					{ "ReadProcessMemory4 (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] {
							0x0f, 0x84, 0xff, 0xff, 0xff, 0xff, 0x83, 0x7d, 0xec, 0x10, 0x0f, 0x85, 0xff, 0xff, 0xff, 0xff, 0x80, 
							0x7d, 0xd8, 0xe9, 0x8b, 0x7d, 0x1c, 0x75},
						Value = new byte[] {
							0x0f, 0x84, 0xff, 0xff, 0xff, 0xff, 0x83, 0x7d, 0xec, 0x20, 0x0f, 0x85, 0xff, 0xff, 0xff, 0xff, 0x80, 
							0x7d, 0xa8, 0xe9, 0x8b, 0x7d, 0x1c, 0x75} }
					},
					// 8B45D9         mov         eax,[ebp][-027]	--> mov eax,[ebp][-057]
					// 8B4B04         mov         ecx,[ebx][4]      --> <removed>
					// 29F8           sub         eax,edi
					// 01C8           add         eax,ecx           --> add eax,[ebx][4]
					// 8945D9         mov         [ebp][-027],eax	--> mov [ebp][-57], eax
					// 89F8           mov         eax,edi
					// 29C8           sub         eax,ecx			--> sub eax,[ebx][4]
					// 83C013         add         eax,013
					// 894318         mov         [ebx][018],eax
					// 0F1045D8       movups      xmm0,[ebp][-028]	--> movups xmm0,[ebp][-058]
					// 0F1106         movups      [esi],xmm0
					// 0F1006         movups      xmm0,[esi]        --> movups xmm0,[ebp][-048]
					// 0F1145D8       movups      [ebp][-028],xmm0	--> movups [esi+010],xmm0 
					// C645D8B8       mov         b,[ebp][-028],0B8 --> mov b,[ebp][-48],0b8
					// 8B4601         mov         eax,[esi][1]
					// 8945D9         mov         [ebp][-027],eax	--> mov [ebp][-047],eax
					// C645DDBA       mov         b,[ebp][-023],0BA --> mov b,[ebp][-043],0BA
					// 8D4718         lea         eax,[edi][018]
					// 8945DE         mov         [ebp][-022],eax	--> mov [ebp][-042],eax
					// 66C745E2FFE2   mov         w,[ebp][-01E],0E2FF --> mov w,[ebp][-03e],0E2FF
					// 8B4318         mov         eax,[ebx][018]
					// 85C0           test        eax,eax
					// 7410           jz         .000465595
					// C645D8E9       mov         b,[ebp][-028],0E9	-> mov b,[ebp-58],0e9
					// 8945D9         mov         [ebp][-027],eax	-> mov [ebp][-057],eax
					// C745D005000000 mov         d,[ebp][-030],5	-> mov d,[ebp][-050],5
					{ "ReadProcessMemory5 (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] {
							0x8b, 0x45, 0xd9, 0x8b, 0x4b, 0x04, 0x29, 0xf8, 0x01, 0xc8, 0x89, 0x45, 0xd9, 0x89, 0xf8, 0x29, 0xc8, 
							0x83, 0xc0, 0x13},
						Value = new byte[] {
							0x8b, 0x45, 0xa9, 0x29, 0xf8, 0x03, 0x43, 0x04, 0x89, 0x45, 0xa9, 0x89, 0xf8, 0x2b, 0x43, 0x04, 0x83,
							0xc0, 0x13, 0x89, 0x43, 0x18, 0x0f, 0x10, 0x45, 0xA8, 0x0F, 0x11, 0x06, 0x0f, 0x10, 0x45, 0xB8, 0x0F,
							0x11, 0x46, 0x10, 0xc6, 0x45, 0xb8, 0xb8, 0x8b, 0x46, 0x01, 0x89, 0x45, 0xb9, 0xc6, 0x45, 0xbd, 0xba,
							0x8d, 0x47, 0x18, 0x89, 0x45, 0xbe, 0x66, 0xc7, 0x45, 0xc2, 0xff, 0xe2, 0xff, 0xff, 0xff, 0xff, 0xff,
							0xff, 0xff, 0xc6, 0x45, 0xa8, 0xe9, 0x89, 0x45, 0xa9, 0xc7, 0x45, 0xb0, 0x05} }
					},
					// 89F8           mov         eax,edi
					// 83C428         add         esp,028			--> add esp,058
					// 5E             pop         esi
					// 5F             pop         edi
					// 5B             pop         ebx
					// 5D             pop         ebp
					// C22000         retn        00020
					{ "ReadProcessMemory6 (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] { 0x89, 0xf8, 0x83, 0xc4, 0x28, 0x5e, 0x5f, 0x5b, 0x5d, 0xc2, 0x20, 0x00},
						Value = new byte[] {0x89, 0xf8, 0x83, 0xc4, 0x58, 0x5e, 0x5f, 0x5b, 0x5d, 0xc2, 0x20, 0x00} }
					},
				},
			},
			new ReplaceItem
			{
				FileName = "msedge_elf.dll",
				NullifyCertificateTable = true,
				Imports = new Dictionary<string,string> { { "kernel32.dll", "KERNEL64.dll" } },
				DelayImports = new Dictionary<string,string>(),
				Binary = new Dictionary<string, BinaryDescriptor> 
				{
					{ "bcrypt", new BinaryDescriptor {
					    Key = Encoding.Unicode.GetBytes("bcryptprimitives"),
					    Value = Encoding.Unicode.GetBytes("xcryptprimitives") }
					},
					{ "binary-1", new BinaryDescriptor {
						ArchType = ArchTypeE.x64,
						Key = new byte [] {
							0x4c, 0x89, 0xFF, 0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0xFc, 0xFF, 0xFF, 0xFF, 0x48, 0x21, 0xc8, 0xb9,
							0x01, 0x00, 0x00, 0x00},
						Value = new byte[] {
							0x4c, 0x89, 0xFF, 0x48, 0xc7, 0xc1, 0x00, 0x00, 0x00, 0xfe, 0x90, 0x90, 0x90} }
					},
					{ "binary-1 (alt)", new BinaryDescriptor {
						ArchType = ArchTypeE.x64,
						Key = new byte [] { 
							0x48, 0x89, 0xd1, 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0xFc, 0xFF, 0xFF, 0xFF, 0x48, 0x21, 0xc1},
						Value = new byte[] {
							0x48, 0x89, 0xd1, 0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0xfe, 0x90, 0x90, 0x90, 0x48, 0x21, 0xc1} }
					},
					{ "binary-2", new BinaryDescriptor {
						ArchType = ArchTypeE.x64,
						Key = new byte [] {
							0x8a, 0x07, 0x49, 0xbd, 0x00, 0x00, 0x00, 0x00, 0xFc, 0xFF, 0xFF, 0xFF, 0x4c, 0x23, 0x6c, 0x24, 0xFF,
							0x4c},
						Value = new byte[] {
							0x8a, 0x07, 0x49, 0xc7, 0xc5, 0x00, 0x00, 0x00, 0xfe, 0x90, 0x90, 0x90} }
					},
					{ "binary-2 (alt 1)", new BinaryDescriptor {
						ArchType = ArchTypeE.x64,
						Key = new byte [] {
							0xb6, 0x07, 0x49, 0xbc, 0x00, 0x00, 0x00, 0x00, 0xFc, 0xFF, 0xFF, 0xFF, 0x4c, 0x23, 0x64, 0x24, 0xFF,
							0x4c}, 
						Value = new byte[] {
							0xb6, 0x07, 0x49, 0xc7, 0xc4, 0x00, 0x00, 0x00, 0xfe, 0x90, 0x90, 0x90} }
					},
					{ "binary-2 (alt 2)", new BinaryDescriptor {
						ArchType = ArchTypeE.x64,
						Key = new byte [] {
							0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0xFc, 0xFF, 0xFF, 0xFF, 0x48, 0x23, 0x4c, 0x24, 0xFF}, 
						Value = new byte[] {
							0x48, 0xc7, 0xc1, 0x00, 0x00, 0x00, 0xfe, 0x90, 0x90, 0x90, 0x48, 0x23, 0x4c, 0x24, 0xFF} }
					},
					{ "RtlGetDeviceFamilyInfoEnum", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte [] {
					        0x56, 0x57, 0x48, 0x83, 0xec, 0x38, 0x48, 0x8b, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x31, 0xE0, 0x48,
					        0x89, 0x44, 0x24, 0x30, 0xC7, 0x44, 0x24, 0x2c, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8D, 0x0D, 0xFF, 0xFF,
					        0xFF, 0x00, 0xFF, 0x15, 0xFF, 0xFF, 0xFF}, 
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90, 0x48, 0x8b, 0x05} }
					},
					{ "RtlGetDeviceFamilyInfoEnum (x86)", new BinaryDescriptor {
					    ArchType = ArchTypeE.x86,
					    Key = new byte [] {
					        0x55, 0x89, 0xe5, 0x56, 0x83, 0xec, 0x08, 0xa1, 0xFF, 0xFF, 0xFF, 0xFF, 0x31, 0xe8, 0x89, 0x45, 0xf8,
					        0xc7, 0x45, 0xf4, 0xff, 0xff, 0xff, 0xff, 0x68, 0xff, 0xff, 0xff, 0xFF, 0xff, 0x15 },
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x56, 0x83, 0xec, 0x08, 0xa1} }
					},
					{ "binary-3", new BinaryDescriptor {
						ArchType = ArchTypeE.x64,
						Key = new byte [] {
							0xd7, 0x00, 0x00, 0x00, 0x48, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xc7, 0x44, 0x24},
						Value = new byte[] {
							0xd7, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc6, 0x00, 0x00, 0x00, 0x02, 0x90, 0x90, 0x90} }
					},
					{ "binary-3 (alt)", new BinaryDescriptor {
						ArchType = ArchTypeE.x64,
						Key = new byte [] {
							0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x48, 0x89, 0xca},
						Value = new byte[] {
							0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x89, 0xca} }
					},
				}
			},
			new ReplaceItem 
			{
				FileName = "mspdf.dll",
				NullifyCertificateTable = true,
				Imports = new Dictionary<string,string> { { "kernel32.dll", "KERNEL64.dll" } },
				DelayImports = new Dictionary<string,string>(),
				Binary = new Dictionary<string, BinaryDescriptor> 
				{
					{ "bcrypt", new BinaryDescriptor {
					    Key = Encoding.Unicode.GetBytes("bcryptprimitives"),
					    Value = Encoding.Unicode.GetBytes("xcryptprimitives") }
					},
					{ "RtlGetDeviceFamilyInfoEnum", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte [] {
					        0x56, 0x57, 0x48, 0x83, 0xec, 0x38, 0x48, 0x8b, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x31, 0xE0, 0x48,
					        0x89, 0x44, 0x24, 0x30, 0xC7, 0x44, 0x24, 0x2c, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8D, 0x0D, 0xFF, 0xFF,
					        0xFF, 0x00, 0xFF, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8D, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89,
					        0xC1},
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90, 0x48, 0x8b, 0x05} }
					},
					{ "RtlGetDeviceFamilyInfoEnum (x86)", new BinaryDescriptor {
					    ArchType = ArchTypeE.x86,
					    Key = new byte [] {
					        0x55, 0x89, 0xe5, 0x56, 0x83, 0xec, 0x08, 0xa1, 0xFF, 0xFF, 0xFF, 0xFF, 0x31, 0xe8, 0x89, 0x45, 0xf8,
					        0xc7, 0x45, 0xf4, 0xff, 0xff, 0xff, 0xff, 0x68, 0xff, 0xff, 0xff, 0xFF, 0xff, 0x15 },
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x56, 0x83, 0xec, 0x08, 0xa1} }
					},
				}
			},
			new ReplaceItem
			{ 
				FileName = "telclient.dll",
				NullifyCertificateTable = true,
				Imports = new Dictionary<string,string> { { "kernel32.dll", "KERNEL64.dll" } },
				DelayImports = new Dictionary<string,string>(),
				Binary = new Dictionary<string, BinaryDescriptor>
				{
					{ "bcrypt", new BinaryDescriptor {
					    Key = Encoding.Unicode.GetBytes("bcryptprimitives"), 
					    Value = Encoding.Unicode.GetBytes("xcryptprimitives") }
					},
					{ "RtlGetDeviceFamilyInfoEnum", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte [] {
					        0x56, 0x57, 0x48, 0x83, 0xec, 0x38, 0x48, 0x8b, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x31, 0xE0, 0x48,
					        0x89, 0x44, 0x24, 0x30, 0xC7, 0x44, 0x24, 0x2c, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8D, 0x0D, 0xFF, 0xFF,
					        0xFF, 0x00, 0xFF, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8D, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89,
					        0xC1},
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90, 0x48, 0x8b, 0x05} }
					},
					{ "RtlGetDeviceFamilyInfoEnum (x86)", new BinaryDescriptor {
					    ArchType = ArchTypeE.x86,
					    Key = new byte [] {
					        0x55, 0x89, 0xe5, 0x56, 0x83, 0xec, 0x08, 0xa1, 0xFF, 0xFF, 0xFF, 0xFF, 0x31, 0xe8, 0x89, 0x45, 0xf8,
					        0xc7, 0x45, 0xf4, 0xff, 0xff, 0xff, 0xff, 0x68, 0xff, 0xff, 0xff, 0xFF, 0xff, 0x15 },
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x56, 0x83, 0xec, 0x08, 0xa1} }
					},
				}
			},
			new ReplaceItem
			{
				FileName = "elevation_service.exe",
				NullifyCertificateTable = true,
				Imports = new Dictionary<string,string> { { "kernel32.dll", "KERNEL64.dll" } },
				DelayImports = new Dictionary<string,string>(),
				Binary = new Dictionary<string, BinaryDescriptor>
				{
					{ "bcrypt", new BinaryDescriptor {
					    Key = Encoding.Unicode.GetBytes("bcryptprimitives"),
					    Value = Encoding.Unicode.GetBytes("xcryptprimitives") }
					},
					//{ "RtlGetDevice", new BinaryDescriptor {
					//	Key = new byte[] {
					//		0x48, 0x8d, 0x0d, 0xFF, 0xFF, 0xFF, 0x00, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8d, 0x15, 0xFF, 0xFF,
					//		0xFF, 0x00, 0x48, 0x89, 0xc1, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x3a, 0x31, 0xf6,
					//		0x48, 0x8d, 0x7c, 0x24, 0x2c, 0x31, 0xc9, 0x48, 0x89, 0xfa, 0x45, 0x31, 0xc0, 0xff, 0x15, 0xFF, 0xFF, 0xFF,
					//		0x00, 0x8b, 0x07, 0x83, 0xf8, 0x03, 0x75, 0x16},
					//	Value = new byte[] {
					//		0x48, 0x31, 0xc0, 0x48, 0x89, 0xc6, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
					//		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
					//		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
					//		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}
					//} }
				}
			},
			new ReplaceItem
			{
				FileName = "dxcompiler.dll",
				NullifyCertificateTable = true,
				Imports = new Dictionary<string,string>(),
				DelayImports = new Dictionary<string,string>(),
				Binary = new Dictionary<string, BinaryDescriptor>()
			},
			new ReplaceItem
			{
				FileName = "dxil.dll",
				NullifyCertificateTable = true,
				Imports = new Dictionary<string,string>(),
				DelayImports = new Dictionary<string,string>(),
				Binary = new Dictionary<string, BinaryDescriptor>()
			},
			new ReplaceItem
			{
				FileName = "ie_to_edge_stub.exe",
				NullifyCertificateTable = true,
				Imports = new Dictionary<string,string>(),
				DelayImports = new Dictionary<string,string>(),
				Binary = new Dictionary<string, BinaryDescriptor>()
			},
			new ReplaceItem
			{
				FileName = "libEGL.dll",
				NullifyCertificateTable = true,
				Imports = new Dictionary<string,string>(),
				DelayImports = new Dictionary<string,string>(),
				Binary = new Dictionary<string, BinaryDescriptor>()
			},
			new ReplaceItem
			{
				FileName = "libGLESv2.dll",
				NullifyCertificateTable = true,
				Imports = new Dictionary<string,string>(),
				DelayImports = new Dictionary<string,string>(),
				Binary = new Dictionary<string, BinaryDescriptor>()
			},
			new ReplaceItem
			{
				FileName = "vk_swiftshader.dll",
				NullifyCertificateTable = true,
				Imports = new Dictionary<string,string>(),
				DelayImports = new Dictionary<string,string>(),
				Binary = new Dictionary<string, BinaryDescriptor>()
			},
			new ReplaceItem
			{
				FileName = "vulkan-1.dll",
				NullifyCertificateTable = true,
				Imports = new Dictionary<string,string>(),
				DelayImports = new Dictionary<string,string>(),
				Binary = new Dictionary<string, BinaryDescriptor>()
			},
			new ReplaceItem
			{
				FileName = "identity_helper.exe",
				NullifyCertificateTable = true,
				Imports = new Dictionary<string,string> { { "kernel32.dll", "KERNEL64.dll" }, { "user32.dll", "USER64.dll" } },
				DelayImports = new Dictionary<string,string>(),
				Binary = new Dictionary<string, BinaryDescriptor> 
				{
					{ "bcrypt", new BinaryDescriptor {
					    Key = Encoding.Unicode.GetBytes("bcryptprimitives"),
					    Value = Encoding.Unicode.GetBytes("xcryptprimitives") }
					},
					{ "RtlGetDeviceFamilyInfoEnum", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte[] {
					        0x56, 0x57, 0x48, 0x83, 0xec, 0x38, 0x48, 0x8b, 0x05, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x31, 0xe0, 0x48,
					        0x89, 0x44, 0x24, 0x30, 0xc7, 0x44, 0x24, 0x2c, 0xFF, 0xFF, 0xFF, 0xff, 0x48, 0x8d, 0x0d, 0xFF, 0xFF,
					        0xFF, 0x00, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8d, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89,
					        0xc1, 0xFF},
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90, 0x48, 0x8b, 0x05} }
					},
					{ "RtlGetDeviceFamilyInfoEnum (x86)", new BinaryDescriptor {
					    ArchType = ArchTypeE.x86,
					    Key = new byte [] {
					        0x55, 0x89, 0xe5, 0x56, 0x83, 0xec, 0x08, 0xa1, 0xFF, 0xFF, 0xFF, 0xFF, 0x31, 0xe8, 0x89, 0x45, 0xf8,
					        0xc7, 0x45, 0xf4, 0xff, 0xff, 0xff, 0xff, 0x68, 0xff, 0xff, 0xff, 0xFF, 0xff, 0x15 },
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x56, 0x83, 0xec, 0x08, 0xa1} }
					},
				}
			},
			new ReplaceItem
			{
				FileName = "msedge_pwa_launcher.exe",
				NullifyCertificateTable = true,
				Imports = new Dictionary<string,string> { { "kernel32.dll", "KERNEL64.dll" } },
				DelayImports = new Dictionary<string,string>(),
				Binary = new Dictionary<string, BinaryDescriptor>
				{
					{ "bcrypt", new BinaryDescriptor {
					    Key = Encoding.Unicode.GetBytes("bcryptprimitives"),
					    Value = Encoding.Unicode.GetBytes("xcryptprimitives") }
					},
					{ "RtlGetDeviceFamilyInfoEnum", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte[] {
					        0x56, 0x57, 0x48, 0x83, 0xec, 0x38, 0x48, 0x8b, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x31, 0xe0, 0x48,
					        0x89, 0x44, 0x24, 0x30, 0xc7, 0x44, 0x24, 0x2c, 0xFF, 0xFF, 0xFF, 0xff, 0x48, 0x8d, 0x0d, 0xFF, 0xFF,
					        0xFF, 0x00, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8d, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89,
					        0xc1, 0xFF},
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90, 0x48, 0x8b, 0x05}}
					},
					{ "RtlGetDeviceFamilyInfoEnum (x86)", new BinaryDescriptor {
					    ArchType = ArchTypeE.x86,
					    Key = new byte [] {
					        0x55, 0x89, 0xe5, 0x56, 0x83, 0xec, 0x08, 0xa1, 0xFF, 0xFF, 0xFF, 0xFF, 0x31, 0xe8, 0x89, 0x45, 0xf8,
					        0xc7, 0x45, 0xf4, 0xff, 0xff, 0xff, 0xff, 0x68, 0xff, 0xff, 0xff, 0xFF, 0xff, 0x15 },
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x56, 0x83, 0xec, 0x08, 0xa1} }
					},
				}
			},
			new ReplaceItem
			{
				FileName = "msedgewebview2.exe",
				NullifyCertificateTable = true,
				Imports = new Dictionary<string,string> { { "kernel32.dll", "KERNEL64.dll" } },
				DelayImports = new Dictionary<string,string> { { "userenv.dll", "USERENX.dll" } },
				Binary = new Dictionary<string, BinaryDescriptor>
				{
					{ "bcrypt", new BinaryDescriptor {
					    Key = Encoding.Unicode.GetBytes("bcryptprimitives"),
					    Value = Encoding.Unicode.GetBytes("xcryptprimitives") }
					},
					{ "RtlGetDeviceFamilyInfoEnum", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte[] {
					        0x56, 0x48, 0x83, 0xec, 0x30, 0x48, 0x8b, 0x05, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x31, 0xe0, 0x48, 0x89,
					        0x44, 0x24, 0xFF, 0xc7, 0x44, 0x24, 0x24, 0xFF, 0xFF, 0xFF, 0xff, 0x48, 0x8d, 0x0d, 0xFF, 0xFF, 0xFF,
					        0x00, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8d, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xc1,
					        0xFF},
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x90, 0x90, 0x48, 0x8b, 0x05}
					} },
					{ "RtlGetDeviceFamilyInfoEnum (x86)", new BinaryDescriptor {
					    ArchType = ArchTypeE.x86,
					    Key = new byte [] {
					        0x55, 0x89, 0xe5, 0x56, 0x83, 0xec, 0x08, 0xa1, 0xFF, 0xFF, 0xFF, 0xFF, 0x31, 0xe8, 0x89, 0x45, 0xf8,
					        0xc7, 0x45, 0xf4, 0xff, 0xff, 0xff, 0xff, 0x68, 0xff, 0xff, 0xff, 0xFF, 0xff, 0x15},
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x56, 0x83, 0xec, 0x08, 0xa1} }
					},
					{ "TerminateProcess", new BinaryDescriptor {
						ArchType = ArchTypeE.x64,
						Key = new byte[] {
							0x40, 0x84, 0xed, 0x75, 0x14, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xC1, 0xBA, 0x62, 0x1b,
							0x00, 0x00 },
						Value = new byte[] {
							0x90, 0x90, 0x90, 0xeb, 0x14, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xC1, 0xBA, 0x62, 0x1b,
							0x00, 0x00 },
					} },
					// FF15442E6300    call        CreateEventW
					// C70300000000    mov         d,[ebx],0
					// 89D9            mov         ecx,ebx
					// 50              push        eax
					// E85BDBF1FF      call       .00042DA94
					// 8D8D44FFFFFF    lea         ecx,[ebp][-0000000BC]
					// E85C9A0500      call       .0005699A0
					// 84C0            test        al,al
					// 741B            jz         .00050FF63; --> 1
					// 8A8549FFFFFF    mov         al,[ebp][-0000000B7]
					// 888538FFFFFF    mov         [ebp][-0000000C8],al
					// 89D9            mov         ecx,ebx
					// E875DBF1FF      call       .00042DAD0
					// 8A8538FFFFFF    mov         al,[ebp][-0000000C8]
					// EB1B            jmps       .00050FF7E
					// 89D9          1 mov         ecx,ebx
					// E866DBF1FF      call       .00042DAD0
					// FF15042F6300    call        GetCurrentProcess
					// 68621B0000      push        000001B62
					// 50              push        eax
					// FF1558316300    call        TerminateProcess
					{ "TerminateProcess (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte[] {
							0x84, 0xc0, 0x74, 0x1b, 0x8a, 0x85, 0xFF, 0xFF, 0xFF, 0xff, 0x88, 0x85, 0xFF, 0xFF, 0xFF, 0xFF, 0x89,
							0xd9 },
						Value = new byte[] {
							0x90, 0x90, 0x90, 0x90, 0x8a, 0x85, 0xFF, 0xFF, 0xFF, 0xff, 0x88, 0x85, 0xFF, 0xFF, 0xFF, 0xFF, 0x89,
							0xd9 },
					} },
					{ "TerminateProcess (alt)", new BinaryDescriptor {
						ArchType = ArchTypeE.x64,
						Key = new byte[] {
							0x84, 0xc0, 0x75, 0x31, 0xe8, 0xff, 0xff, 0xff, 0xff, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89,
							0xC1, 0xBA, 0x62, 0x1b, 0x00, 0x00 },
						Value = new byte[] {
							0x90, 0x90, 0xeb, 0x31, 0xe8, 0xff, 0xff, 0xff, 0xff, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89,
							0xC1, 0xBA, 0x62, 0x1b, 0x00, 0x00 },
					} },
					{ "TerminateProcess (alt 2)", new BinaryDescriptor {
						ArchType = ArchTypeE.x64,
						Key = new byte [] {
							0x84, 0xc0, 0x74, 0x24, 0x40, 0x8a, 0x69, 0x05, 0xe8, 0xff, 0xff, 0xFF, 0xFF, 0xeb, 0x32},
						Value = new byte[] {
							0x90, 0x90, 0x90, 0x90, 0x40, 0x8a, 0x69, 0x05, 0xe8, 0xff, 0xff, 0xFF, 0xFF, 0xeb, 0x32} }
					},
					// 55             push        ebp
					// 89E5           mov         ebp,esp
					// 53             push        ebx
					// 57             push        edi
					// 56             push        esi
					// 83EC28         sub         esp,028            --> sub esp,058
					// 89CB           mov         ebx,ecx
					// 8B7D1C         mov         edi,[ebp][01C]
					// 0F106508       movups      xmm4,[ebp][8]
					// A140706300     mov         eax,[000637040]
					{ "ReadProcessMemory (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] { 0x55, 0x89, 0xe5, 0x53, 0x57, 0x56, 0x83, 0xec, 0x28, 0x89, 0xcb, 0x8b, 0x7d, 0x1c},
						Value = new byte[] {0x55, 0x89, 0xe5, 0x53, 0x57, 0x56, 0x83, 0xec, 0x58, 0x89, 0xcb, 0x8b, 0x7d, 0x1c} }
					},
					// 660F76C0                       pcmpeqd     xmm0,xmm0
					// 8D45D8                         lea         eax,[ebp][-028]	--> lea eax,[ebp][-058]
					// F30F7F00                       movdqu      [eax],xmm0
					{ "ReadProcessMemory2 (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] {0x66, 0x0f, 0x76, 0xc0, 0x8d, 0x45, 0xd8, 0xf3, 0x0f, 0x7f, 0x00},
						Value = new byte[] {0x66, 0x0f, 0x76, 0xc0, 0x8d, 0x45, 0xa8, 0xf3, 0x0f, 0x7f, 0x00} }
					},
					// 8D4DEC         lea         ecx,[ebp][-014]
					// C701FFFFFFFF   mov         d,[ecx],-1
					// 51             push        ecx
					// 6A10           push        010				--> push 020
					// 50             push        eax
					// FF7304         push        d,[ebx][4]
					// FF7310         push        d,[ebx][010]
					// FF15B4306300   call        ReadProcessMemory
					// 85C0           test        eax,eax
					{ "ReadProcessMemory3 (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] {
							0xc7, 0x01, 0xff, 0xff, 0xff, 0xff, 0x51, 0x6a, 0x10, 0x50, 0xff, 0x73, 0x04, 0xff, 0x73, 0x10, 0xff, 
							0x15, 0xff, 0xff, 0xff, 0xff, 0x85, 0xc0},
						Value = new byte[] {
							0xc7, 0x01, 0xff, 0xff, 0xff, 0xff, 0x51, 0x6a, 0x20, 0x50, 0xff, 0x73, 0x04, 0xff, 0x73, 0x10, 0xff,
							0x15, 0xff, 0xff, 0xff, 0xff, 0x85, 0xc0} }
					},
					// 0F841A010000   jz         .000465646
					// 837DEC10       cmp         d,[ebp][-014],010	--> cmp d,[ebp][-014],020
					// 0F8510010000   jnz        .000465646
					// 807DD8E9       cmp         b,[ebp][-028],0E9 --> cmp b,[ebp][-058],0E9
					// 8B7D1C         mov         edi,[ebp][01C]
					// 7517           jnz        .000465556 
					{ "ReadProcessMemory4 (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] {
							0x0f, 0x84, 0xff, 0xff, 0xff, 0xff, 0x83, 0x7d, 0xec, 0x10, 0x0f, 0x85, 0xff, 0xff, 0xff, 0xff, 0x80, 
							0x7d, 0xd8, 0xe9, 0x8b, 0x7d, 0x1c, 0x75},
						Value = new byte[] {
							0x0f, 0x84, 0xff, 0xff, 0xff, 0xff, 0x83, 0x7d, 0xec, 0x20, 0x0f, 0x85, 0xff, 0xff, 0xff, 0xff, 0x80, 
							0x7d, 0xa8, 0xe9, 0x8b, 0x7d, 0x1c, 0x75} }
					},
					// 8B45D9         mov         eax,[ebp][-027]	--> mov eax,[ebp][-057]
					// 8B4B04         mov         ecx,[ebx][4]      --> <removed>
					// 29F8           sub         eax,edi
					// 01C8           add         eax,ecx           --> add eax,[ebx][4]
					// 8945D9         mov         [ebp][-027],eax	--> mov [ebp][-57], eax
					// 89F8           mov         eax,edi
					// 29C8           sub         eax,ecx			--> sub eax,[ebx][4]
					// 83C013         add         eax,013
					// 894318         mov         [ebx][018],eax
					// 0F1045D8       movups      xmm0,[ebp][-028]	--> movups xmm0,[ebp][-058]
					// 0F1106         movups      [esi],xmm0
					// 0F1006         movups      xmm0,[esi]        --> movups xmm0,[ebp][-048]
					// 0F1145D8       movups      [ebp][-028],xmm0	--> movups [esi+010],xmm0 
					// C645D8B8       mov         b,[ebp][-028],0B8 --> mov b,[ebp][-48],0b8
					// 8B4601         mov         eax,[esi][1]
					// 8945D9         mov         [ebp][-027],eax	--> mov [ebp][-047],eax
					// C645DDBA       mov         b,[ebp][-023],0BA --> mov b,[ebp][-043],0BA
					// 8D4718         lea         eax,[edi][018]
					// 8945DE         mov         [ebp][-022],eax	--> mov [ebp][-042],eax
					// 66C745E2FFE2   mov         w,[ebp][-01E],0E2FF --> mov w,[ebp][-03e],0E2FF
					// 8B4318         mov         eax,[ebx][018]
					// 85C0           test        eax,eax
					// 7410           jz         .000465595
					// C645D8E9       mov         b,[ebp][-028],0E9	-> mov b,[ebp-58],0e9
					// 8945D9         mov         [ebp][-027],eax	-> mov [ebp][-057],eax
					// C745D005000000 mov         d,[ebp][-030],5	-> mov d,[ebp][-050],5
					{ "ReadProcessMemory5 (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] {
							0x8b, 0x45, 0xd9, 0x8b, 0x4b, 0x04, 0x29, 0xf8, 0x01, 0xc8, 0x89, 0x45, 0xd9, 0x89, 0xf8, 0x29, 0xc8, 
							0x83, 0xc0, 0x13},
						Value = new byte[] {
							0x8b, 0x45, 0xa9, 0x29, 0xf8, 0x03, 0x43, 0x04, 0x89, 0x45, 0xa9, 0x89, 0xf8, 0x2b, 0x43, 0x04, 0x83,
							0xc0, 0x13, 0x89, 0x43, 0x18, 0x0f, 0x10, 0x45, 0xA8, 0x0F, 0x11, 0x06, 0x0f, 0x10, 0x45, 0xB8, 0x0F,
							0x11, 0x46, 0x10, 0xc6, 0x45, 0xb8, 0xb8, 0x8b, 0x46, 0x01, 0x89, 0x45, 0xb9, 0xc6, 0x45, 0xbd, 0xba,
							0x8d, 0x47, 0x18, 0x89, 0x45, 0xbe, 0x66, 0xc7, 0x45, 0xc2, 0xff, 0xe2, 0xff, 0xff, 0xff, 0xff, 0xff,
							0xff, 0xff, 0xc6, 0x45, 0xa8, 0xe9, 0x89, 0x45, 0xa9, 0xc7, 0x45, 0xb0, 0x05} }
					},
					// 89F8           mov         eax,edi
					// 83C428         add         esp,028			--> add esp,058
					// 5E             pop         esi
					// 5F             pop         edi
					// 5B             pop         ebx
					// 5D             pop         ebp
					// C22000         retn        00020
					{ "ReadProcessMemory6 (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] { 0x89, 0xf8, 0x83, 0xc4, 0x28, 0x5e, 0x5f, 0x5b, 0x5d, 0xc2, 0x20, 0x00},
						Value = new byte[] {0x89, 0xf8, 0x83, 0xc4, 0x58, 0x5e, 0x5f, 0x5b, 0x5d, 0xc2, 0x20, 0x00} }
					},
				}
			},
			new ReplaceItem
			{
				FileName = "notification_helper.exe",
				NullifyCertificateTable = true,
				Imports = new Dictionary<string,string> { { "kernel32.dll", "KERNEL64.dll" } },
				DelayImports = new Dictionary<string,string>(),
				Binary = new Dictionary<string, BinaryDescriptor>
				{
					{ "bcrypt", new BinaryDescriptor {
					    Key = Encoding.Unicode.GetBytes("bcryptprimitives"),
					    Value = Encoding.Unicode.GetBytes("xcryptprimitives") }
					},
					{ "RtlGetDeviceFamilyInfoEnum", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte[] {
					        0x56, 0x57, 0x48, 0x83, 0xec, 0x38, 0x48, 0x8b, 0x05, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x31, 0xe0, 0x48,
					        0x89, 0x44, 0x24, 0x30, 0xc7, 0x44, 0x24, 0x2c, 0xFF, 0xFF, 0xFF, 0xff, 0x48, 0x8d, 0xFF, 0xFF, 0xFF,
					        0xFF, 0x00, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8d, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89,
					        0xc1, 0xFF},
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90, 0x48, 0x8b, 0x05}
					} },
					{ "RtlGetDeviceFamilyInfoEnum (x86)", new BinaryDescriptor {
					    ArchType = ArchTypeE.x86,
					    Key = new byte [] {
					        0x55, 0x89, 0xe5, 0x56, 0x83, 0xec, 0x08, 0xa1, 0xFF, 0xFF, 0xFF, 0xFF, 0x31, 0xe8, 0x89, 0x45, 0xf8,
					        0xc7, 0x45, 0xf4, 0xff, 0xff, 0xff, 0xff, 0x68, 0xff, 0xff, 0xff, 0xFF, 0xff, 0x15},
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x56, 0x83, 0xec, 0x08, 0xa1} }
					},
				}
			},
			new ReplaceItem
			{
				FileName = "pwahelper.exe",
				NullifyCertificateTable = true,
				Imports = new Dictionary<string,string> { { "kernel32.dll", "KERNEL64.dll" } },
				DelayImports = new Dictionary<string,string>(),
				Binary = new Dictionary<string, BinaryDescriptor>
				{
					{ "bcrypt", new BinaryDescriptor {
					    Key = Encoding.Unicode.GetBytes("bcryptprimitives"),
					    Value = Encoding.Unicode.GetBytes("xcryptprimitives") }
					},
				}
			},
			new ReplaceItem
			{
				FileName = "dual_engine_adapter_x64.dll",
				NullifyCertificateTable = true,
				Imports = new Dictionary<string,string> { { "kernel32.dll", "KERNEL64.dll" } },
				DelayImports = new Dictionary<string,string>(),
				Binary = new Dictionary<string, BinaryDescriptor>()
				{
					{ "bcrypt", new BinaryDescriptor { 
					    Key = Encoding.Unicode.GetBytes("bcryptprimitives"),
					    Value = Encoding.Unicode.GetBytes("xcryptprimitives") }
					},
				}
			},
			new ReplaceItem
			{
				FileName = "dual_engine_adapter_x86.dll",
				NullifyCertificateTable = true,
				Imports = new Dictionary<string,string> { { "kernel32.dll", "KERNEL64.dll" } },
				DelayImports = new Dictionary<string,string>(),
				Binary = new Dictionary<string, BinaryDescriptor>()
				{
					{ "bcrypt", new BinaryDescriptor { 
					    Key = Encoding.Unicode.GetBytes("bcryptprimitives"),
					    Value = Encoding.Unicode.GetBytes("xcryptprimitives") }
					},
				}
			},
			new ReplaceItem
			{
				FileName = "mojo_core.dll",
				NullifyCertificateTable = true,
				Imports = new Dictionary<string,string> { { "kernel32.dll", "KERNEL64.dll" } },
				DelayImports = new Dictionary<string,string>(),
				Binary = new Dictionary<string, BinaryDescriptor>
				{
					{ "bcrypt", new BinaryDescriptor { 
					    Key = Encoding.Unicode.GetBytes("bcryptprimitives"),
					    Value = Encoding.Unicode.GetBytes("xcryptprimitives") }
					},
					{ "RtlGetDeviceFamilyInfoEnum", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte [] {
					        0x56, 0x57, 0x48, 0x83, 0xEC, 0x38, 0x48, 0x8B, 0x05, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x31, 0xE0, 0x48,
					        0x89, 0x44, 0x24, 0x30, 0xC7, 0x44, 0x24, 0x2C, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8D, 0x0D, 0xFF, 0xFF,
					        0xFf, 0x00, 0xFF, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8D, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89,
					        0xC1, 0xFF, 0x15, 0xFF, 0xFF, 0xff, 0x00}, 
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90, 0x48, 0x8B, 0x05 } }
					},
					{ "RtlGetDeviceFamilyInfoEnum (x86)", new BinaryDescriptor {
					    ArchType = ArchTypeE.x86,
					    Key = new byte [] {
					        0x55, 0x89, 0xe5, 0x56, 0x83, 0xec, 0x08, 0xa1, 0xFF, 0xFF, 0xFF, 0xFF, 0x31, 0xe8, 0x89, 0x45, 0xf8,
					        0xc7, 0x45, 0xf4, 0xff, 0xff, 0xff, 0xff, 0x68, 0xff, 0xff, 0xff, 0xFF, 0xff, 0x15},
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x56, 0x83, 0xec, 0x08, 0xa1} }
					},
				}
			},
			new ReplaceItem
			{
				FileName = "embeddedbrowserwebview.dll",
				NullifyCertificateTable = true,
				Imports = new Dictionary<string,string> { { "kernel32.dll", "KERNEL64.dll" } },
				DelayImports = new Dictionary<string,string> { { "user32.dll", "USER64.dll" } },
				Binary = new Dictionary<string, BinaryDescriptor>
				{ 
					{ "bcrypt", new BinaryDescriptor {
					    Key = Encoding.Unicode.GetBytes("bcryptprimitives"),
					    Value = Encoding.Unicode.GetBytes("xcryptprimitives") }
					},
					{ "RtlGetDeviceFamilyInfoEnum", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte [] {
					        0x56, 0x57, 0x48, 0x83, 0xEC, 0x38, 0x48, 0x8B, 0x05, 0xFF, 0xff, 0xFF, 0x00, 0x48, 0x31, 0xE0, 0x48,
					        0x89, 0x44, 0x24, 0x30, 0xC7, 0x44, 0x24, 0x2C, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8D, 0x0D, 0xFF, 0xFF,
					        0xFF, 0x00, 0xFF, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8D, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89,
					        0xC1, 0xFF, 0x15, 0xFF, 0xFF, 0xFF, 0x00}, 
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90, 0x48, 0x8B, 0x05 } }
					},
					{ "RtlGetDeviceFamilyInfoEnum (x86)", new BinaryDescriptor {
					    ArchType = ArchTypeE.x86,
					    Key = new byte [] {
					        0x55, 0x89, 0xe5, 0x56, 0x83, 0xec, 0x08, 0xa1, 0xFF, 0xFF, 0xFF, 0xFF, 0x31, 0xe8, 0x89, 0x45, 0xf8,
					        0xc7, 0x45, 0xf4, 0xff, 0xff, 0xff, 0xff, 0x68, 0xff, 0xff, 0xff, 0xFF, 0xff, 0x15},
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x56, 0x83, 0xec, 0x08, 0xa1} }
					},
				}
			},
			new ReplaceItem
			{
				FileName = "msedge.dll",
				NullifyCertificateTable = true,
				Imports = new Dictionary<string,string> { { "kernel32.dll", "KERNEL64.dll" } },
				DelayImports = new Dictionary<string,string>
				{
					{ "user32.dll", "USER64.dll" },
					{ "mfplat.dll", "XFPlat.DLL" },
					{ "userenv.dll", "USERENX.dll" },
					{ "netapi32.dll", "NETAPI64.dll"},
					{ "winhttp.dll", "WINXTTP.dll"},
					{ "bcrypt.dll", "xcrypt.dll"},
					{ "bcryptprimitives.dll", "xcryptprimitives.dll"},
				},
				Binary = new Dictionary<string, BinaryDescriptor>
				{
					{ "bcrypt", new BinaryDescriptor {
					    Key = Encoding.Unicode.GetBytes("bcryptprimitives"),
					    Value = Encoding.Unicode.GetBytes("xcryptprimitives") }
					},
					{ "edge/ntp", new BinaryDescriptor {
					    Key = Encoding.ASCII.GetBytes("https://ntp.msn.com/edge/ntp\0"),
					    Value = Encoding.ASCII.GetBytes("about:blank\0\0\0\0\0\x1\0"),
					    UpdateType = UpdateType.NtpOnly
					}},
					{ "edge/ntp-2", new BinaryDescriptor {
					    Key = Encoding.ASCII.GetBytes("https://ntp.msn.com/edge/ntp?\0"),
					    Value = Encoding.ASCII.GetBytes("about:blank\0\0\0\0\0\x2\0"),
					    UpdateType = UpdateType.NtpOnly
					}},
					{ "local-ntp", new BinaryDescriptor {
					    Key = Encoding.ASCII.GetBytes("chrome-search://local-ntp/local-ntp.html\0"),
					    Value = Encoding.ASCII.GetBytes("about:blank\0\0\0\0\0\x3\0"),
					    UpdateType = UpdateType.NtpOnly
					}},
					//{ "RtlGetDeviceFamilyInfoEnum", new BinaryDescriptor {
					//    ArchType = ArchTypeE.x64,
					//    Key = new byte [] {
					//        0x56, 0x48, 0x83, 0xec, 0x30, 0x48, 0x8b, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x31, 0xE0, 0x48, 0x89,
					//        0x44, 0x24, 0x28, 0xC7, 0x44, 0x24, 0x24, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8d, 0x0D, 0xFF, 0xFF, 0xFF,
					//        0xFF, 0xFF, 0x15, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8d, 0x15, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x89, 0xC1,
					//        0xFF, 0x15, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x85, 0xc0, 0x74, 0xFF, 0x48, 0x8d, 0x74, 0x24, 0x24, 0x31,
					//        0xc9}, 
					//    Value = new byte[] {
					//        0x31, 0xc0, 0xc3, 0x90, 0x90, 0x48, 0x8b, 0x05 } }
					//},
					//{ "RtlGetDeviceFamilyInfoEnum (x86)", new BinaryDescriptor {
					//    ArchType = ArchTypeE.x86,
					//    Key = new byte [] {
					//        0x55, 0x89, 0xe5, 0x56, 0x83, 0xec, 0x08, 0xa1, 0xFF, 0xFF, 0xFF, 0xFF, 0x31, 0xe8, 0x89, 0x45, 0xf8,
					//        0xc7, 0x45, 0xf4, 0xff, 0xff, 0xff, 0xff, 0x68, 0xff, 0xff, 0xff, 0xFF, 0xff, 0x15},
					//    Value = new byte[] {
					//        0x31, 0xc0, 0xc3, 0x56, 0x83, 0xec, 0x08, 0xa1} }
					//},
					// 48B9AAAAAAAAAAAAAAAA mov         rcx,AAAAAAAA`AAAAAAAA
					// 4C8D4C2440		lea         r9,[rsp][040]
					// 498909			mov         [r9],rcx
					// 4489642430		mov         [rsp][030],r12d
					// 4489642428		mov         [rsp][028],r12d
					// C744242002000000	mov         d,[rsp][020],2
					// 4889C1			mov         rcx,rax
					// 4C89F2			mov         rdx,r14
					// 4989C0			mov         r8,rax
					// FF156059B40E		call        DuplicateHandle
					// 4189C6			mov         r14d,eax
					// 85C0				test        eax,eax
					// 740B				jz         .00000001`811C9BD2
					// 488B4C2440		mov         rcx,[rsp][040]
					// FF150E58B40E		call        CloseHandle
					// 4585F6           test        r14d,r14d
					// 0F94C0           setz        al
					// 85ED				test        ebp,ebp
					// 0F95C1           setnz       cl
					// 30C1				xor         cl,al
					// 0F84ED000000		jz         .00000001`811C9CD2
					// 4C8BA424C0000000 mov         r12,[rsp][0000000C0]
					// 31C0				xor         eax,eax
					{ "DuplicateHandle", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte [] {
					        0x0e, 0x45, 0x85, 0xff, 0x0f, 0x94, 0xc0, 0x85, 0xff, 0x0f, 0x95, 0xc1, 0x30, 0xc1, 0x0f, 0x84, 0xff,
					        0xff, 0x00, 0x00, 0xff, 0x8b },
					    Value = new byte[] {
					        0x0e, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
					        0x90, 0x90, 0x90, 0xff, 0x8b } }
					},
					//// 6A00           push        0
					//// 6A00           push        0
					//// 6A02           push        2
					//// 8D4C242C       lea         ecx,[esp][02C]
					//// 51             push        ecx
					//// 50             push        eax
					//// 57             push        edi
					//// 50             push        eax
					//// FF15A428551D   call        DuplicateHandle
					//// 89C7           mov         edi,eax
					//// 85C0           test        eax,eax
					//// 740A           jz         .014C808EB
					//// FF742420       push        d,[esp][020]
					//// FF150028551D   call        CloseHandle
					//// 85FF           test        edi,edi
					//// 0F94C0         setz        al
					//// 837C240C00     cmp         d,[esp][00C],0
					//// 0F95C1         setnz       cl
					//// 30C1           xor         cl,al
					//// 0F84DE000000   jz         .014C809DE
					//{ "DuplicateHandle (x86)", new BinaryDescriptor {
					//    ArchType = ArchTypeE.x86,
					//    Key = new byte [] {
					//        0x85, 0xff, 0x0f, 0x94, 0xc0, 0x83, 0x7c, 0x24, 0x0c, 0x00, 0x0f, 0x95, 0xc1, 0x30, 0xc1, 0x0f, 0x84,
					//        0xff, 0xff, 0x00, 0x00, 0x89 },
					//    Value = new byte[] {
					//        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
					//        0x90, 0x90, 0x90, 0x90, 0x89 } }
					//},
					// 4C8D8C2480000000               lea         r9,[rsp][000000080]
					// 4D8921                         mov         [r9],r12
					// 44896C2430                     mov         [rsp][030],r13d
					// 44896C2428                     mov         [rsp][028],r13d
					// C744242002000000               mov         d,[rsp][020],2
					// 4889C1                         mov         rcx,rax
					// 4889FA                         mov         rdx,rdi
					// 4989C0                         mov         r8,rax
					// FF153912D40F                   call        DuplicateHandle
					// 89C5                           mov         ebp,eax
					// 85C0                           test        eax,eax
					// 740E                           jz         .00000001`8024243B
					// 488B8C2480000000               mov         rcx,[rsp][000000080]
					// FF15E510D40F                   call        CloseHandle
					// 85ED                           test        ebp,ebp
					// 0F94C0                         setz        al
					// 85DB                           test        ebx,ebx
					// 0F95C1                         setnz       cl
					// 30C1                           xor         cl,al
					// 0F847A010000                   jz         .00000001`802425C7
					// 4C8DBC2480000000               lea         r15,[rsp][000000080]
					{ "DuplicateHandle - 2", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte [] {
					        0x0f, 0x85, 0xff, 0x0f, 0x94, 0xc0, 0x85, 0xff, 0x0f, 0x95, 0xc1, 0x30, 0xc1, 0x0f, 0x84, 0xff, 0xff,
					        0x00, 0x00, 0xff, 0x8d },
					    Value = new byte[] {
					        0x0f, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
					        0x90, 0x90, 0xff, 0x8d } }
					},
					// FF15B4E7911D		call        DuplicateHandle
					// 89C3             mov         ebx,eax
					// 85C0				test        eax,eax
					// 7409             jz         .014DDF86B
					// FF7620			push        d,[esi][020]
					// FF1514E7911D     call        CloseHandle
					// 85DB				test        ebx,ebx
					// 0F94C0			setz        al
					// 837E0800         cmp         d,[esi][8],0
					// 0F95C1			setnz       cl
					// 30C1				xor         cl,al
					// 0F841E010000     jz         .014DDF99D
					// 89661C			mov         [esi][01C],esp
					// 50				push        eax
					// 83EC0C			sub         esp,00C
					//{ "DuplicateHandle - 2 (x86)", new BinaryDescriptor {
					//    ArchType = ArchTypeE.x86,
					//    Key = new byte [] {
					//        0xff, 0x15, 0xff, 0xff, 0xff, 0xff, 0x85, 0xff, 0x0f, 0x94, 0xc0, 0x83, 0x7e, 0x08, 0x00, 0x0f, 0x95,
					//        0xc1, 0x30, 0xc1, 0x0f, 0x84, 0xff, 0xff, 0x00, 0x00, 0x89, 0x66, 0x1c },
					//    Value = new byte[] {
					//        0xff, 0x15, 0xff, 0xff, 0xff, 0xff, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
					//        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x89, 0x66, 0x1c} }
					//},
					//{ "binary1", new BinaryDescriptor {
					//    ArchType = ArchTypeE.x64,
					//    Key = new byte [] {
					//        0x0f, 0x48, 0x83, 0xbc, 0x24, 0x60, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x84, 0x4e, 0x01, 0x00, 0x00, 0x4C },
					//    Value = new byte[] {
					//        0x0f, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x4C } }
					//},
					// 8B4110          mov         eax,[ecx][010]
					// 50              push        eax
					// E8532E3BFE      call       .01520BECE
					// 83C404          add         esp,4
					// 84C0            test        al,al
					// B802080000      mov         eax,000000802
					// B900090000      mov         ecx,000000900
					// 0F45C8          cmovnz      ecx,eax
					// 898D20FFFFFF    mov         [ebp][-0000000E0],ecx
					// 8B8DDCFEFFFF    mov         ecx,[ebp][-000000124]
					// E97D020000      jmp        .016E5931B
					//{ "binary1 (x86)", new BinaryDescriptor {
					//    ArchType = ArchTypeE.x86,
					//    Key = new byte [] {
					//        0x83, 0xc4, 0x04, 0x84, 0xc0, 0xb8, 0x02, 0x08, 0x00, 0x00, 0xb9, 0x00, 0x09, 0x00, 0x00, 0x0f, 0x45 },
					//    Value = new byte[] {
					//        0x83, 0xc4, 0x04, 0x84, 0xc0, 0xb8, 0x02, 0x08, 0x00, 0x00, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x45 } }
					//},
					//{ "binary2", new BinaryDescriptor {
					//    ArchType = ArchTypeE.x64,
					//    Key = new byte [] {
					//        0x00, 0x40, 0x00, 0xff, 0x00, 0x0f, 0x95, 0xc0, 0xFF, 0x85, 0xed, 0x0f, 0x94, 0xc1, 0x20, 0xc1, 0x80,
					//        0xf9, 0x01, 0x0f, 0x84, 0xff, 0xff, 0x00, 0x00, 0x4c },
					//    Value = new byte[] {
					//        0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
					//        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x4c } }
					//},
					// 55               push        ebp
					// 89E5             mov         ebp,esp
					// 53               push        ebx
					// 57               push        edi
					// 56               push        esi
					// 83EC1C           sub         esp,01C
					// 8D7D08           lea         edi,[ebp][8]
					// A140705B1D       mov         eax,[01D5B7040]
					// 31E8             xor         eax,ebp
					// 8945F0           mov         [ebp][-010],eax
					// 8B07             mov         eax,[edi]
					// F7472080002000   test        d,[edi][020],000200080
					// 740A             jz         .01829520B
					// 837F3400         cmp         d,[edi][034],0
					// 0F8414010000     jz         .01829531F
					// 8D7538           lea         esi,[ebp][038]
					// 8945D8           mov         [ebp][-028],eax
					// C700FFFFFFFF     mov         d,[eax],-1
					// 6864010000       push        000000164
					// E85FFF7903       call       .01BA35180
					//{ "binary2 (x86)", new BinaryDescriptor {
					//    ArchType = ArchTypeE.x86,
					//    Key = new byte [] {
					//        0x8b, 0x07, 0xf7, 0x47, 0xff, 0x80, 0x00, 0x20, 0x00, 0x74, 0x0a, 0x83, 0x7f, 0x34, 0x00, 0x0f, 0x84,
					//        0x14, 0xff, 0xff, 0xff, 0x8d},
					//    Value = new byte[] {
					//        0x8b, 0x07, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
					//        0x90, 0x90, 0x90, 0x90, 0x8d} }
					//},
					//{ "binary2 (alt)", new BinaryDescriptor {
					//    ArchType = ArchTypeE.x64,
					//    Key = new byte [] {
					//        0xf7, 0x84, 0x24, 0x58, 0x01, 0x00, 0x00, 0x40, 0x00, 0xff, 0x00, 0x0f, 0x95, 0xc0, 0x48, 0x83, 0xbc,
					//        0x24, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x94, 0xff, 0x20, 0xff, 0x80, 0xff, 0x01, 0x0f, 0x84, 0xff,
					//        0xff, 0x00, 0x00 },
					//    Value = new byte[] {
					//        0xf7, 0x84, 0x24, 0x58, 0x01, 0x00, 0x00, 0x40, 0x00, 0xff, 0x00, 0x0f, 0x95, 0xc0, 0x48, 0x83, 0xbc,
					//        0x24, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x94, 0xff, 0x20, 0xff, 0x80, 0xff, 0x01, 0x90, 0x90, 0x90,
					//        0x90, 0x90, 0x90 } }
					//},
					// 55               push        ebp
					// 89E5             mov         ebp,esp
					// 53               push        ebx
					// 57               push        edi
					// 56               push        esi
					// 83EC20           sub         esp,020
					// 8D7D08           lea         edi,[ebp][8]
					// A14000781D       mov         eax,[01D780040]
					// 31E8             xor         eax,ebp
					// 8945F0           mov         [ebp][-010],eax
					// 8B07             mov         eax,[edi]
					// F7472040001000   test        d,[edi][020],000100040
					// 740A             jz         .018E2E2EB
					// 837F3400         cmp         d,[edi][034],0
					// 0F8420010000     jz         .018E2E40B
					// 8D7538           lea         esi,[ebp][038]
					// 8945D4           mov         [ebp][-02C],eax
					// C700FFFFFFFF     mov         d,[eax],-1
					// 68B4010000       push        0000001B4
					// E89FEFD802       call       .01BBBD2A0
					//{ "binary2 (alt - x86)", new BinaryDescriptor {
					//    ArchType = ArchTypeE.x86,
					//    Key = new byte [] {
					//        0x8b, 0x07, 0xf7, 0x47, 0x20, 0x40, 0x00, 0xff, 0x00, 0x74, 0x0a, 0x83, 0x7f, 0xff, 0x00, 0x0f, 0x84,
					//        0xFF, 0xff, 0xff, 0xff, 0x8d},
					//    Value = new byte[] {
					//        0x8b, 0x07, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
					//        0x90, 0x90, 0x90, 0x90, 0x8d} }
					//},
					// 55               push        ebp
					// 89E5             mov         ebp,esp
					// 53               push        ebx
					// 57               push        edi
					// 56               push        esi
					// 83E4F0           and         esp,0F0
					// 81EC90000000     sub         esp,000000090
					// A14020981D       mov         eax,[01D982040]
					// 31E8             xor         eax,ebp
					// 89842488000000   mov         [esp][000000088],eax
					// 8B4130           mov         eax,[ecx][030]
					// 85C0             test        eax,eax
					// 7407             jz         .014C76055
					// 8A4004           mov         al,[eax][4]
					// 84C0             test        al,al
					// 741A             jz         .014C7606F
					// 31DB             xor         ebx,ebx
					// 8B8C2488000000   mov         ecx,[esp][000000088]
					// 31E9             xor         ecx,ebp
					// E862041307       call       .01BDA64C7
					// 89D8             mov         eax,ebx
					// 8D65F4           lea         esp,[ebp][-00C]
					// 5E               pop         esi
					//{ "binary3 (x86)", new BinaryDescriptor {
					//    ArchType = ArchTypeE.x86,
					//    Key = new byte [] {
					//        0x55, 0x89, 0xe5, 0x53, 0x57, 0x56, 0x83, 0xe4, 0xf0, 0x81, 0xec, 0xff, 0xff, 0xff, 0xff, 0xa1, 0xff,
					//        0xFF, 0xff, 0xff, 0x31, 0xe8, 0x89, 0x84, 0x24, 0xff, 0xff, 0xff, 0xff, 0x8b, 0x41, 0xff, 0x85, 0xc0,
					//        0x74, 0x07, 0x8a, 0x40, 0x04, 0x84, 0xc0, 0x74, 0xff, 0x31, 0xdb},
					//    Value = new byte[] {
					//        0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x83, 0xe4, 0xf0, 0x81, 0xec, 0xff, 0xff, 0xff, 0xff, 0xa1, 0xff,
					//        0xFF, 0xff, 0xff, 0x31, 0xe8, 0x89, 0x84, 0x24, 0xff, 0xff, 0xff, 0xff, 0x8b, 0x41, 0xff, 0x85, 0xc0,
					//        0x74, 0x07, 0x8a, 0x40, 0x04, 0x84, 0xc0, 0x74, 0xff, 0x31, 0xdb} }
					//},
					// 55				push        ebp
					// 89E5             mov         ebp,esp
					// 56				push        esi
					// A1F86FB31D       mov         eax,[01DB36FF8]
					// 8B0D7049B01D     mov         ecx,[01DB04970]
					// 648B152C000000   mov         edx,fs:[00000002C]
					// 8B0C8A           mov         ecx,[edx][ecx]*4
					// 3B8104000000     cmp         eax,[ecx][4]
					// 0F8FFD000000     jg         .014D8A732
					// 833D7C97B31D00   cmp         d,[01DB3977C],0
					// 0F84E5000000     jz         .014D8A727
					// BE03000000       mov         esi,3
					// E834020000       call       .014D8A880
					// 84C0             test        al,al
					// 0F85D9000000     jnz        .014D8A72D
					// BE02000000       mov         esi,2
					//{ "binary4 (x86)", new BinaryDescriptor {
					//    ArchType = ArchTypeE.x86,
					//    Key = new byte [] {
					//        0x55, 0x89, 0xe5, 0x56, 0xa1, 0xff, 0xff, 0xff, 0xff, 0x8b, 0x0d, 0xff, 0xff, 0xff, 0xff, 0x64, 0x8b,
					//        0x15, 0xff, 0xff, 0xff, 0xff, 0x8b, 0x0c, 0x8a, 0x3b, 0x81, 0x04, 0x00, 0x00, 0x00, 0x0f, 0x8f, 0xff,
					//        0x00, 0x00, 0x00, 0x83, 0x3d, 0xff, 0xff, 0xff, 0xff, 0x00, 0x0f, 0x84, 0xff, 0x00, 0x00, 0x00, 0xbe,
					//        0x03, 0x00, 0x00, 0x00},
					//    Value = new byte[] {
					//        0x31, 0xc0, 0xc3, 0x56, 0xa1, 0xff, 0xff, 0xff, 0xff, 0x8b, 0x0d, 0xff, 0xff, 0xff, 0xff, 0x64, 0x8b,
					//        0x15, 0xff, 0xff, 0xff, 0xff, 0x8b, 0x0c, 0x8a, 0x3b, 0x81, 0x04, 0x00, 0x00, 0x00, 0x0f, 0x8f, 0xff,
					//        0x00, 0x00, 0x00, 0x83, 0x3d, 0xff, 0xff, 0xff, 0xff, 0x00, 0x0f, 0x84, 0xff, 0x00, 0x00, 0x00, 0xbe,
					//        0x03, 0x00, 0x00, 0x00} }
					//},
					// 68F86FB31D		push        01DB36FF8
					// E86DB20107       call       .01BDA59A9
					// 83C404           add         esp,4
					// 833DF86FB31DFF   cmp         d,[01DB36FF8],-1
					// 0F85E9FEFFFF     jnz        .014D8A635
					// E8AF030000       call       .014D8AB00			--> mov eax, 0
					// A3F46FB31D       mov         [01DB36FF4],eax
					// 68B8C0B41D       push        01DB4C0B8
					// E863FD0207       call       .01BDB8F23
					// 83C404           add         esp,4
					// E9CDFEFFFF       jmp        .014D89095
					//{ "binary5 (x86)", new BinaryDescriptor {
					//    ArchType = ArchTypeE.x86,
					//    Key = new byte [] {
					//        0x68, 0xff, 0xff, 0xff, 0x1d, 0xe8, 0xff, 0xff, 0xff, 0xff, 0x83, 0xc4, 0x04, 0x83, 0x3d, 0xff, 0xff,
					//        0xff, 0x1d, 0xff, 0x0f, 0x85, 0xe9, 0xfe, 0xff, 0xff, 0xe8, 0xaf, 0x03, 0x00, 0x00, 0xa3, 0xff, 0xff,
					//        0xff, 0x1d, 0x68, 0xff, 0xff, 0xff, 0x1d, 0xe8, 0xff, 0xff, 0xff, 0xff, 0x83, 0xc4, 0x04, 0xe9, 0xcd,
					//        0xfe, 0xff, 0xff},
					//    Value = new byte[] {
					//        0x68, 0xff, 0xff, 0xff, 0x1d, 0xe8, 0xff, 0xff, 0xff, 0xff, 0x83, 0xc4, 0x04, 0x83, 0x3d, 0xff, 0xff,
					//        0xff, 0x1d, 0xff, 0x0f, 0x85, 0xe9, 0xfe, 0xff, 0xff, 0xb8, 0x00, 0x00, 0x00, 0x00, 0xa3, 0xff, 0xff,
					//        0xff, 0x1d, 0x68, 0xff, 0xff, 0xff, 0x1d, 0xe8, 0xff, 0xff, 0xff, 0xff, 0x83, 0xc4, 0x04, 0xe9, 0xcd,
					//        0xfe, 0xff, 0xff} }
					//},
					// 40				inc         eax
					// 83F810           cmp         eax,010
					// 774F             ja         .014DCC6D1
					// B9CF000100       mov         ecx,0000100CF
					// 0FA3C1           bt          ecx,eax				--> nop
					// 7345             jnc        .014DCC6D1			--> nop
					// 6AFE             push        -2
					// 56               push        esi
					// FF157CEC911D     call        SetThreadPriority
					//{ "SetThreadPriority (x86)", new BinaryDescriptor {
					//    ArchType = ArchTypeE.x86,
					//    Key = new byte [] {
					//        0x40, 0x83, 0xf8, 0x10, 0x77, 0xff, 0xb9, 0xff, 0xff, 0xff, 0xff, 0x0f, 0xa3, 0xc1, 0x73, 0xff, 0x6a,
					//        0xfe, 0x56, 0xff, 0x15, 0xff, 0xff, 0xff, 0xff},
					//    Value = new byte[] {
					//        0x40, 0x83, 0xf8, 0x10, 0x77, 0xff, 0xb9, 0xff, 0xff, 0xff, 0xff, 0x90, 0x90, 0x90, 0x90, 0x90, 0x6a,
					//        0xfe, 0x56, 0xff, 0x15, 0xff, 0xff, 0xff, 0xff} }
					//},
					// 4C89F1           mov         rcx,r14
					// BA01000000       mov         edx,1
					// 41B80F000010     mov         r8d,01000000F				--> mov r8d, 0000f
					// FF15D8784B0C     call        RegNotifyChangeKeyValue
					// 85C0             test        eax,eax
					{ "RegNotifyChangeKeyValue", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte [] { 
					        0xBA, 0x01, 0x00, 0x00, 0x00, 0x41, 0xB8, 0x0F, 0x00, 0x00, 0x10, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0xFF,
					        0x85, 0xC0 },
					    Value = new byte[] {
					        0xBA, 0x01, 0x00, 0x00, 0x00, 0x41, 0xB8, 0x0F, 0x00, 0x00, 0x00, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0xFF,
					        0x85, 0xC0 } }
					},
					// 6A01             push        1
					// 50               push        eax
					// 680F000010       push        01000000F					--> push 00000f
					// 6A01             push        1
					// FF75DC           push        d,[ebp][-024]
					// FF158CB9731D     call        RegNotifyChangeKeyValue
					// 85C0             test        eax,eax
					// 7422             jz         .014C680CF
					//{ "RegNotifyChangeKeyValue (x86)", new BinaryDescriptor {
					//    ArchType = ArchTypeE.x86,
					//    Key = new byte [] { 0x01, 0x50, 0x68, 0x0F, 0x00, 0x00, 0x10, 0x6a, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x15 },
					//    Value = new byte[] {0x01, 0x50, 0x68, 0x0F, 0x00, 0x00, 0x00, 0x6a, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x15 } }
					//},
					{ "TerminateProcess", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte [] {
					        0x84, 0xFF, 0x75, 0x14, 0xff, 0x15, 0xFF, 0xff, 0xff, 0xff, 0x48, 0x89, 0xc1, 0xba, 0x5e, 0x1b, 0x00,
					        0x00 },
					    Value = new byte[] {
					        0x84, 0xff, 0xeb, 0x14, 0xff, 0x15, 0xff, 0xff, 0xff, 0xff, 0x48, 0x89, 0xc1, 0xba, 0x5e, 0x1b, 0x00,
					        0x00 } }
					},
					// FF152C28551D     call        CreateEventW
					// C70300000000     mov         d,[ebx],0
					// 89D9             mov         ecx,ebx
					// 50               push        eax
					// E835FC15FA       call       .0101696CE
					// 8D8D44FFFFFF     lea         ecx,[ebp][-0000000BC]
					// E81CF77101       call       .0177291C0
					// 84C0             test        al,al					--> nop
					// 741B             jz         .016009AC3; -> 1			--> nop
					// 8A8549FFFFFF     mov         al,[ebp][-0000000B7]
					// 888538FFFFFF     mov         [ebp][-0000000C8],al
					// 89D9             mov         ecx,ebx
					// E8251816FA       call       .01016B2E0
					// 8A8538FFFFFF     mov         al,[ebp][-0000000C8]
					// EB1B             jmps       .016009ADE
					// 89D9           1 mov         ecx,ebx
					// E8161816FA       call       .01016B2E0
					// FF157429551D     call        GetCurrentProcess
					// 68621B0000       push        000001B62
					// 50               push        eax
					// FF15A42D551D     call        TerminateProcess
					//{ "TerminateProcess (x86)", new BinaryDescriptor { 
					//    ArchType = ArchTypeE.x86,
					//    Key = new byte[] {
					//        0x84, 0xc0, 0x74, 0x1b, 0x8a, 0x85, 0xFF, 0xFF, 0xFF, 0xff, 0x88, 0x85, 0xFF, 0xFF, 0xFF, 0xFF, 0x89,
					//        0xd9 },
					//    Value = new byte[] {
					//        0x90, 0x90, 0x90, 0x90, 0x8a, 0x85, 0xFF, 0xFF, 0xFF, 0xff, 0x88, 0x85, 0xFF, 0xFF, 0xFF, 0xFF, 0x89,
					//        0xd9 },
					//} },
					{ "TerminateProcess-a", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte [] {
					        0x06, 0x48, 0x85, 0xc9, 0x74, 0x12, 0x48, 0x8d, 0x15, 0xFF, 0xFF, 0xFF, 0xff, 0x48, 0x83, 0xc4, 0x28,
					        0x48, 0xff, 0x25 },
					    Value = new byte[] {
					        0x06, 0x48, 0x85, 0xc9, 0xeb, 0x12, 0x48, 0x8d, 0x15, 0xff, 0xFf, 0xff, 0xff, 0x48, 0x83, 0xc4, 0x28,
					        0x48, 0xff, 0x25 } }
					},
					{ "TerminateProcess-b", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte [] { 0x08, 0x00, 0x00, 0xb9, 0x00, 0x09, 0x00, 0x00, 0x0f, 0x45, 0xc8, 0x89, 0x8c, 0x24 },
					    Value = new byte[] {0x08, 0x00, 0x00, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x45, 0xc8, 0x89, 0x8c, 0x24 } }
					},
					{ "TerminateProcess-c", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte [] {
					        0x48, 0x83, 0xbc, 0x24, 0x28, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x84, 0x19, 0x01, 0x00, 0x00, 0x4c, 0x8b,
					        0xac, 0x24},
					    Value = new byte[] {
					        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x4C, 0x8B,
					        0xAC, 0x24
					    } }
					},
					{ "TerminateProcess-c(alt)", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte [] {
					        0x48, 0x83, 0xbc, 0x24, 0xff, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x84, 0xff, 0xff, 0x00, 0x00, 0x48, 0x89,
					        0xbc, 0x24, 0x98, 0x00, 0x00, 0x8b, 0xb4, 0x24},
					    Value = new byte[] {
					        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x48, 0x89,
					        0xbC, 0x24, 0x98, 0x00, 0x00, 0x8b, 0xb4, 0x24
					    } }
					},
					{ "TerminateProcess-c(alt2)", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte [] {
					        0x48, 0x83, 0x39, 0x00, 0x0f, 0x84, 0xff, 0xff, 0x00, 0x00, 0x44, 0x89, 0xc5, 0x49, 0x89, 0xFF, 0x48,
					        0x8b, 0x72, 0x08},
					    Value = new byte[] {
					        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x44, 0x89, 0xc5, 0x49, 0x89, 0xFF, 0x48,
					        0x8b, 0x72, 0x08
					    } }
					},
					{ "TerminateProcess-c(alt3)", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte [] {
					        0xe8, 0xff, 0xff, 0xff, 0xff, 0x48, 0x83, 0x7d, 0x00, 0x00, 0x0f, 0x84, 0xff, 0xff, 0x00, 0x00, 0x48,
					        0x8d, 0x8c, 0x24},
					    Value = new byte[] {
					        0xe8, 0xff, 0xff, 0xff, 0xff, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x48,
					        0x8d, 0x8c, 0x24
					    } }
					},
					{ "TerminateProcess-c(alt4)", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte [] {
					        0xe8, 0xff, 0xff, 0xff, 0xff, 0x49, 0x83, 0x3f, 0x00, 0x0f, 0x84, 0xff, 0xff, 0x00, 0x00, 0x48, 0x8d,
					        0x8c, 0x24, 0xff, 0xff, 0xff, 0xff, 0x48, 0x8d, 0xbc, 0x24},
					    Value = new byte[] {
					        0xe8, 0xff, 0xff, 0xff, 0xff, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x48, 0x8d, 
					        0x8c, 0x24, 0xff, 0xff, 0xff, 0xff, 0x48, 0x8d, 0xbc, 0x24
					    } }
					},
					// 4881ECB8000000		 sub         rsp,0000000B8
					// 4889CE				 mov         rsi,rcx
					// 488B05B6C3900C		 mov         rax,[00000001`8FB34040]
					// 4831E0				 xor         rax,rsp
					// 48898424B0000000		 mov         [rsp][0000000B0],rax
					// E8168CBEFF			 call       .00000001`82E108B0
					// 83F80C				 cmp         eax,0C						--> cmp eax, 2
					// 0F8EB2010000			 jle        .00000001`83227E55
					// 48B8AAAAAAAAAAAAAAAA  mov         rax,AAAAAAAA`AAAAAAAA
					// 488D5C2470            lea         rbx,[rsp][070]
					{ "VersionCheck", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte [] {
					        0x48, 0x89, 0x84, 0x24, 0xff, 0x00, 0x00, 0x00, 0xe8, 0xff, 0xff, 0xff, 0xff, 0x83, 0xf8, 0x0C, 0x0F,
					        0x8E, 0xFF, 0xFF, 0x00, 0x00, 0x48, 0xB8, 0xAA},
					    Value = new byte[] {
					        0x48, 0x89, 0x84, 0x24, 0xff, 0x00, 0x00, 0x00, 0xe8, 0xff, 0xff, 0xff, 0xff, 0x83, 0xf8, 0x02, 0x0F,
					        0x8E, 0xFF, 0xFF, 0x00, 0x00, 0x48, 0xB8, 0xAA
					    } }
					},
					// 4881ECB8000000		 sub         rsp,0000000B8
					// 4889CE				 mov         rsi,rcx
					// 488B05B6C3900C		 mov         rax,[00000001`8FB34040]
					// 4831E0				 xor         rax,rsp
					// 48898424B0000000		 mov         [rsp][0000000B0],rax
					// E8168CBEFF			 call       .00000001`82E108B0
					// 83F80C				 cmp         eax,0C						--> cmp eax, 2
					// 0F8F1C010000          jg         .00000001`83EA4495
					// E8220FC204            call       .00000001`88AC52A0
					// 83F80C                cmp         eax,00C
					// 0F8F0E010000          jg         .00000001`83EA4495
					// E8140FC204            call       .00000001`88AC52A0
					{ "VersionCheck (alt)", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte [] {
					        0x48, 0x89, 0x84, 0x24, 0xff, 0x00, 0x00, 0x00, 0xe8, 0xff, 0xff, 0xff, 0xff, 0x83, 0xf8, 0x0C, 0x0F,
					        0x8F, 0xFF, 0xFF, 0x00, 0x00, 0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0x83, 0xf8, 0x0c, 0x0f, 0x8f, 0xff, 0xff,
					        0xff, 0xff, 0xe8},
					    Value = new byte[] {
					        0x48, 0x89, 0x84, 0x24, 0xff, 0x00, 0x00, 0x00, 0xe8, 0xff, 0xff, 0xff, 0xff, 0x83, 0xf8, 0x02, 0x0F,
					        0x8f, 0xFF, 0xFF, 0x00, 0x00, 0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0x83, 0xf8, 0x0c, 0x0f, 0x8f, 0xff, 0xff,
					        0xff, 0xff, 0xe8
					    } }
					},
					// 83EC4C                sub         esp,04C
					// 89CE                  mov         esi,ecx
					// A14000781D            mov         eax,[01D780040]
					// 31E8                  xor         eax,ebp
					// 8945F0                mov         [ebp][-010],eax
					// E8DAAA02FF            call       .014D02D90
					// 83F80C                cmp         eax,00C				--> cmp eax, 2
					// 8975A8                mov         [ebp][-058],esi
					// 7F24                  jg         .015CD82E2
					//{ "VersionCheck (x86)", new BinaryDescriptor {
					//    ArchType = ArchTypeE.x86,
					//    Key = new byte [] {
					//        0x89, 0x45, 0xff, 0xe8, 0xff, 0xff, 0xff, 0xff, 0x83, 0xf8, 0x0C, 0x89, 0x75, 0xff, 0x7f, 0xFF},
					//    Value = new byte[] {
					//        0x89, 0x45, 0xff, 0xe8, 0xff, 0xff, 0xff, 0xff, 0x83, 0xf8, 0x02, 0x89, 0x75, 0xff, 0x7f, 0xFF
					//    } }
					//},
					// 83EC4C                sub         esp,04C
					// A14060BA1D            mov         eax,[01DBA6040]
					// 31E8                  xor         eax,ebp
					// 8945F0                mov         [ebp][-010],eax
					// E8DAAA02FF            call       .014D02D90
					// 83F80C                cmp         eax,00C				--> cmp eax, 2
					// 7F24                  jg         .0161358DA
					// E8C596F0FE            call       .01503EF80
					// 83F80C                cmp         eax,00C
					// 7F1A                  jg         .0161358DA
					// E8BB96F0FE            call       .01503EF80
					//{ "VersionCheck (alt) (x86)", new BinaryDescriptor {
					//    ArchType = ArchTypeE.x86,
					//    Key = new byte [] {
					//        0xa1, 0xff, 0xff, 0xff, 0xff, 0x31, 0xe8, 0x89, 0x45, 0xf0, 0xe8, 0xff, 0xff, 0xff, 0xff, 0x83,
					//        0xf8, 0x0c, 0x7f, 0x24, 0xe8, 0xff, 0xff, 0xff, 0xff, 0x83, 0xf8 ,0x0c, 0x7f, 0x1a, 0xe8},
					//    Value = new byte[] {
					//        0xa1, 0xff, 0xff, 0xff, 0xff, 0x31, 0xe8, 0x89, 0x45, 0xf0, 0xe8, 0xff, 0xff, 0xff, 0xff, 0x83,
					//        0xf8, 0x02, 0x7f, 0x24, 0xe8, 0xff, 0xff, 0xff, 0xff, 0x83, 0xf8 ,0x0c, 0x7f, 0x1a, 0xe8
					//    } }
					//},
					// 4883EC28              sub         rsp,028
					// E87730FBFF            call       .00000001`82CF1AE0
					// 83F803                cmp         eax,3					--> mov eax, 1
					// 0F94C0                setz        al						--> nop
					// 4883C428              add         rsp,028
					// C3                    retn
					//{ "VersionCheck 2", new BinaryDescriptor {
					//    ArchType = ArchTypeE.x64,
					//    Key = new byte [] {
					//        0xcc, 0xcc, 0x48, 0x83, 0xec, 0x28, 0xe8, 0xff, 0xff, 0xff, 0xff, 0x83, 0xf8, 0x03, 0x0f, 0x94, 0xc0,
					//        0x48, 0x83, 0xc4, 0x28, 0xc3},
					//    Value = new byte[] {
					//        0xcc, 0xcc, 0x48, 0x83, 0xec, 0x28, 0xe8, 0xff, 0xff, 0xff, 0xff, 0xb0, 0x01, 0x90, 0x90, 0x90, 0x90,
					//        0x48, 0x83, 0xc4, 0x28, 0xc3},
					//    }
					//},
					// 83EC18		sub         esp,018
					// A14020981D	mov         eax,[01D982040]
					// 31E8			xor         eax,ebp
					// 8945F4		mov         [ebp][-00C],eax
					// E88917EFFF   call       .014D8A610
					// 83F803		cmp         eax,3
					// 0F84A9000000	jz         .014E98F39
					//{ "VersionCheck 2 (x86)", new BinaryDescriptor {
					//    ArchType = ArchTypeE.x86,
					//    Key = new byte [] {
					//        0x83, 0xec, 0xff, 0xa1, 0xff, 0xff, 0xff, 0xff, 0x31, 0xe8, 0x89, 0x45, 0xf4, 0xe8, 0xff, 0xff, 0xff,
					//        0xff, 0x83, 0xf8, 0x03, 0x0f, 0x84, 0xff, 0x00, 0x00, 0x00},
					//    Value = new byte[] {
					//        0x83, 0xec, 0xff, 0xa1, 0xff, 0xff, 0xff, 0xff, 0x31, 0xe8, 0x89, 0x45, 0xf4, 0xe8, 0xff, 0xff, 0xff,
					//        0xff, 0x83, 0xf8, 0x03, 0xe9, 0xaa, 0x00, 0x00, 0x00, 0x90}
					//    }
					//},
					// Replace IDWriteFactory3 with IDWriteFactory
					{ "IDWriteFactory3", new BinaryDescriptor {
					    Key = new byte [] {
					        0xc3, 0x41, 0x1b, 0x9a, 0xbb, 0xd3, 0x6a, 0x46, 0x87, 0xfc, 0xfe, 0x67, 0x55, 0x6a, 0x3b, 0x65 },
					    Value = new byte[] {
					        0x5a, 0xee, 0x59, 0xb8, 0x38, 0xd8, 0x5b, 0x4b, 0xa2, 0xe8, 0x1a, 0xdc, 0x7d, 0x93, 0xdb, 0x48 } }
					},
				}
			},
		};

			// (ELF) add
		//https://github.com/Blaukovitch/API-MS-WIN_XP
		private static bool Verify_APIMSLibs_status(string rootFolder, string[] exten)
        {
			bool verify_result = true;
			var i = 0;
			Console.WriteLine("  ***************** [ A P I  -  M S ] ***************** ");
			var select_char = @"√";
			foreach (var APIMS_item in APIMSLib_List)
			{
				var actualFiles = Directory.GetFiles(rootFolder, APIMS_item, SearchOption.AllDirectories)
						.Where(x => exten.Contains(Path.GetExtension(x)));

				if (actualFiles.Count() == 0)
				{
					verify_result = false;
					select_char = @" ";
				}
				else
				{
					select_char = @"√";
					i++;
				}
				Console.WriteLine("  {0, -50} {1, -10} ", APIMS_item, select_char);
			}
			Console.WriteLine(" -------------------------------------------------------\r\n Present: {0, -40} {1, -10} ", APIMSLib_List.Length, i);
            return verify_result;
        }

		//(ELF) add
		private static readonly string[] APIMSLib_List = { 
			@"API-MS-WIN-CORE-HANDLE-L1-1-0.dll",
			@"API-MS-WIN-CORE-LIBRARYLOADER-L1-2-0.dll",
			@"API-MS-WIN-CORE-REALTIME-L1-1-1.dll",
			@"API-MS-WIN-CORE-WINRT-ERROR-L1-1-0.dll",
			@"API-MS-WIN-CORE-WINRT-L1-1-0.dll",
			@"API-MS-WIN-CORE-WINRT-STRING-L1-1-0.dll",
			@"API-MS-WIN-POWER-BASE-L1-1-0.dll",
			@"API-MS-WIN-POWER-SETTING-L1-1-1.dll",
			@"API-MS-WIN-SHCORE-SCALING-L1-1-1.dll",
			@"kernel64.dll",
			@"netapi64.dll",
			@"user64.dll",
			@"userenx.dll",
			@"WinXttp.dll",
			@"wldp.dll",
			@"xcryptprimitives.dll",
			@"Xfplat.dll",
		};
	}
}
