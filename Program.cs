/*
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


﻿using System;
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
			bool without_scan_apims_libs = false;
			string rootFolder = args.FirstOrDefault() ?? Directory.GetCurrentDirectory();
			if (!rootFolder.EndsWith(Path.DirectorySeparatorChar.ToString()))
			{
				//add dir check
				FileAttributes attr = File.GetAttributes(rootFolder);
				if ((attr & FileAttributes.Directory) != FileAttributes.Directory)
				{
					rootFolder = Path.GetDirectoryName(Path.GetFullPath(rootFolder));
				}//end if ((attr & FileAttributes.Directory) != FileAttributes.Directory)

				rootFolder += Path.DirectorySeparatorChar;
			}//end if (!rootFolder.EndsWith(Path.DirectorySeparatorChar.ToString()))

			var updateType = UpdateType.None;
			var updateTypeArg = args.Skip(1).FirstOrDefault();
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
			try
			{
				without_scan_apims_libs = true;
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
					foreach (var import in byteReferences)
					{
						Console.WriteLine("  Bytes - {0} at 0x{1:X}", import.Key, import.Value);
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
							0x74, 0x24, 0x40, 0x8a, 0x69, 0x05, 0xe8, 0xff, 0xff, 0xFF, 0xFF, 0xeb, 0x32},
						Value = new byte[] {
							0x90, 0x90, 0x40, 0x8a, 0x69, 0x05, 0xe8, 0xff, 0xff, 0xFF, 0xFF, 0xeb, 0x32} }
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
				FileName = "ie_to_edge_stub.exe",
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
							0x74, 0x24, 0x40, 0x8a, 0x69, 0x05, 0xe8, 0xff, 0xff, 0xFF, 0xFF, 0xeb, 0x32},
						Value = new byte[] {
							0x90, 0x90, 0x40, 0x8a, 0x69, 0x05, 0xe8, 0xff, 0xff, 0xFF, 0xFF, 0xeb, 0x32} }
					},
					// 55             push        ebp
					// 89E5           mov         ebp,esp
					// 53             push        ebx
					// 57             push        edi
					// 56             push        esi
					// 83EC28         sub         esp,028            --> sub esp,048
					// 89CB           mov         ebx,ecx
					// 8B7D1C         mov         edi,[ebp][01C]
					// 0F106508       movups      xmm4,[ebp][8]
					// A140706300     mov         eax,[000637040]
					{ "ReadProcessMemory (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] {0x55, 0x89, 0xe5, 0x53, 0x57, 0x56, 0x83, 0xec, 0x28, 0x89, 0xcb, 0x8b, 0x7d, 0x1c},
						Value = new byte[] {0x55, 0x89, 0xe5, 0x53, 0x57, 0x56, 0x83, 0xec, 0x48, 0x89, 0xcb, 0x8b, 0x7d, 0x1c} }
					},
					// 660F76C0                       pcmpeqd     xmm0,xmm0
					// 8D45D8                         lea         eax,[ebp][-028]	--> lea eax,[ebp][-054]
					// F30F7F00                       movdqu      [eax],xmm0
					{ "ReadProcessMemory2 (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] {0x66, 0x0f, 0x76, 0xc0, 0x8d, 0x45, 0xd8, 0xf3, 0x0f, 0x7f, 0x00},
						Value = new byte[] {0x66, 0x0f, 0x76, 0xc0, 0x8d, 0x45, 0xac, 0xf3, 0x0f, 0x7f, 0x00} }
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
					// 807DD8E9       cmp         b,[ebp][-028],0E9 --> cmp b,[ebp][-054],0E9
					// 8B7D1C         mov         edi,[ebp][01C]
					// 7517           jnz        .000465556 
					{ "ReadProcessMemory4 (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] {
							0x0f, 0x84, 0xff, 0xff, 0xff, 0xff, 0x83, 0x7d, 0xec, 0x10, 0x0f, 0x85, 0xff, 0xff, 0xff, 0xff, 0x80, 
							0x7d, 0xd8, 0xe9, 0x8b, 0x7d, 0x1c, 0x75},
						Value = new byte[] {
							0x0f, 0x84, 0xff, 0xff, 0xff, 0xff, 0x83, 0x7d, 0xec, 0x20, 0x0f, 0x85, 0xff, 0xff, 0xff, 0xff, 0x80, 
							0x7d, 0xac, 0xe9, 0x8b, 0x7d, 0x1c, 0x75} }
					},
					// 8B45D9         mov         eax,[ebp][-027]	--> mov eax,[ebp][-053]
					// 8B4B04         mov         ecx,[ebx][4]      --> <removed>
					// 29F8           sub         eax,edi
					// 01C8           add         eax,ecx           --> add eax,[ebx][4]
					// 8945D9         mov         [ebp][-027],eax	--> mov [ebp][-53], eax
					// 89F8           mov         eax,edi
					// 29C8           sub         eax,ecx			--> sub eax,[ebx][4]
					// 83C013         add         eax,013
					// 894318         mov         [ebx][018],eax
					// 0F1045D8       movups      xmm0,[ebp][-028]	--> movups xmm0,[ebp][-054]
					// 0F1106         movups      [esi],xmm0
					// 0F1006         movups      xmm0,[esi]        --> movups xmm0,[ebp][-044]
					// 0F1145D8       movups      [ebp][-028],xmm0	--> movups [esi+010],xmm0 
					// C645D8B8       mov         b,[ebp][-028],0B8 --> mov b,[ebp][-70],090
					// 8B4601         mov         eax,[esi][1]
					// 8945D9         mov         [ebp][-027],eax	--> mov [ebp][-053],eax
					// C645DDBA       mov         b,[ebp][-023],0BA --> mov b,[ebp][-04f],0BA
					// 8D4718         lea         eax,[edi][018]
					// 8945DE         mov         [ebp][-022],eax	--> mov [ebp][-04e],eax
					// 66C745E2FFE2   mov         w,[ebp][-01E],0E2FF --> mov w,[ebp][-04a],0E2FF
					// 8B4318         mov         eax,[ebx][018]
					// 85C0           test        eax,eax
					// 7410           jz         .000465595
					{ "ReadProcessMemory5 (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] {
							0x8b, 0x45, 0xd9, 0x8b, 0x4b, 0x04, 0x29, 0xf8, 0x01, 0xc8, 0x89, 0x45, 0xd9, 0x89, 0xf8, 0x29, 0xc8, 
							0x83, 0xc0, 0x13},
						Value = new byte[] {
							0x8b, 0x45, 0xad, 0x29, 0xf8, 0x03, 0x43, 0x04, 0x89, 0x45, 0xad, 0x89, 0xf8, 0x2b, 0x43, 0x04, 0x83,
							0xc0, 0x13, 0x89, 0x43, 0x18, 0x0f, 0x10, 0x45, 0xAC, 0x0F, 0x11, 0x06, 0x0f, 0x10, 0x45, 0xBC, 0x0F,
							0x11, 0x46, 0x10, 0xc6, 0x45, 0x90, 0x90, 0x8b, 0x46, 0x01, 0x89, 0x45, 0xad, 0xc6, 0x45, 0xb1, 0xba,
							0x8d, 0x47, 0x18, 0x89, 0x45, 0xb2, 0x66, 0xc7, 0x45, 0xb6, 0xff, 0xe2} }
					},

					// 89F8           mov         eax,edi
					// 83C428         add         esp,028			--> add esp,048
					// 5E             pop         esi
					// 5F             pop         edi
					// 5B             pop         ebx
					// 5D             pop         ebp
					// C22000         retn        00020
					{ "ReadProcessMemory6 (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] { 0x89, 0xf8, 0x83, 0xc4, 0x28, 0x5e, 0x5f, 0x5b, 0x5d, 0xc2, 0x20, 0x00},
						Value = new byte[] {0x89, 0xf8, 0x83, 0xc4, 0x48, 0x5e, 0x5f, 0x5b, 0x5d, 0xc2, 0x20, 0x00} }
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
					{ "RtlGetDeviceFamilyInfoEnum", new BinaryDescriptor {
					    ArchType = ArchTypeE.x64,
					    Key = new byte [] {
					        0x56, 0x48, 0x83, 0xec, 0x30, 0x48, 0x8b, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x31, 0xE0, 0x48, 0x89,
					        0x44, 0x24, 0x28, 0xC7, 0x44, 0x24, 0x24, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8d, 0x0D, 0xFF, 0xFF, 0xFF,
					        0xFF, 0xFF, 0x15, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8d, 0x15, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x89, 0xC1,
					        0xFF, 0x15, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x85, 0xc0, 0x74, 0xFF, 0x48, 0x8d, 0x74, 0x24, 0x24, 0x31,
					        0xc9}, 
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x90, 0x90, 0x48, 0x8b, 0x05 } }
					},
					{ "RtlGetDeviceFamilyInfoEnum (x86)", new BinaryDescriptor {
					    ArchType = ArchTypeE.x86,
					    Key = new byte [] {
					        0x55, 0x89, 0xe5, 0x56, 0x83, 0xec, 0x08, 0xa1, 0xFF, 0xFF, 0xFF, 0xFF, 0x31, 0xe8, 0x89, 0x45, 0xf8,
					        0xc7, 0x45, 0xf4, 0xff, 0xff, 0xff, 0xff, 0x68, 0xff, 0xff, 0xff, 0xFF, 0xff, 0x15},
					    Value = new byte[] {
					        0x31, 0xc0, 0xc3, 0x56, 0x83, 0xec, 0x08, 0xa1} }
					},
					{ "DuplicateHandle", new BinaryDescriptor {
						ArchType = ArchTypeE.x64,
						Key = new byte [] { 0x30, 0xc1, 0x0f, 0x84, 0xFF, 0xFF, 0x00, 0x00, 0x4C, 0x8B, 0xff, 0x24, 0xC0, 0x00 },
						Value = new byte[] {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x4C, 0x8B, 0xff, 0x24, 0xC0, 0x00 } }
					},
					// 6A00           push        0
					// 6A00           push        0
					// 6A02           push        2
					// 8D4C242C       lea         ecx,[esp][02C]
					// 51             push        ecx
					// 50             push        eax
					// 57             push        edi
					// 50             push        eax
					// FF15A428551D   call        DuplicateHandle
					// 89C7           mov         edi,eax
					// 85C0           test        eax,eax
					// 740A           jz         .014C808EB
					// FF742420       push        d,[esp][020]
					// FF150028551D   call        CloseHandle
					// 85FF           test        edi,edi
					// 0F94C0         setz        al
					// 837C240C00     cmp         d,[esp][00C],0
					// 0F95C1         setnz       cl
					// 30C1           xor         cl,al
					// 0F84DE000000   jz         .014C809DE
					{ "DuplicateHandle (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] {
							0x85, 0xff, 0x0f, 0x94, 0xc0, 0x83, 0x7c, 0x24, 0x0c, 0x00, 0x0f, 0x95, 0xc1, 0x30, 0xc1, 0x0f, 0x84,
							0xff, 0xff, 0x00, 0x00, 0x89 },
						Value = new byte[] {
							0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
							0x90, 0x90, 0x90, 0x90, 0x89 } }
					},
					{ "DuplicateHandle - 2", new BinaryDescriptor {
						Key = new byte [] {
							0x0f, 0x85, 0xff, 0x0f, 0x94, 0xc0, 0x85, 0xff, 0x0f, 0x95, 0xc1, 0x30, 0xc1, 0x0f, 0x84, 0xff, 0xff,
							0x00, 0x00, 0xff, 0x8d },
						Value = new byte[] {
							0x0f, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
							0x90, 0x90, 0xff, 0x8d } }
					},
					{ "binary1", new BinaryDescriptor {
						ArchType = ArchTypeE.x64,
						Key = new byte [] {
							0x0f, 0x48, 0x83, 0xbc, 0x24, 0x60, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x84, 0x4e, 0x01, 0x00, 0x00, 0x4C },
						Value = new byte[] {
							0x0f, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x4C } }
					},
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
					{ "binary1 (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] {
							0x83, 0xc4, 0x04, 0x84, 0xc0, 0xb8, 0x02, 0x08, 0x00, 0x00, 0xb9, 0x00, 0x09, 0x00, 0x00, 0x0f, 0x45 },
						Value = new byte[] {
							0x83, 0xc4, 0x04, 0x84, 0xc0, 0xb8, 0x02, 0x08, 0x00, 0x00, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x45 } }
					},
					{ "binary2", new BinaryDescriptor {
						ArchType = ArchTypeE.x64,
						Key = new byte [] {
							0x00, 0x40, 0x00, 0xff, 0x00, 0x0f, 0x95, 0xc0, 0xFF, 0x85, 0xed, 0x0f, 0x94, 0xc1, 0x20, 0xc1, 0x80,
							0xf9, 0x01, 0x0f, 0x84, 0xff, 0xff, 0x00, 0x00, 0x4c },
						Value = new byte[] {
							0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
							0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x4c } }
					},
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
					{ "binary2 (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] {
							0x8b, 0x07, 0xf7, 0x47, 0xff, 0x80, 0x00, 0x20, 0x00, 0x74, 0x0a, 0x83, 0x7f, 0x34, 0x00, 0x0f, 0x84,
							0x14, 0xff, 0xff, 0xff, 0x8d},
						Value = new byte[] {
							0x8b, 0x07, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
							0x90, 0x90, 0x90, 0x90, 0x8d} }
					},
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
					{ "binary2 (alt - x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] {
							0x8b, 0x07, 0xf7, 0x47, 0xff, 0x40, 0x00, 0x10, 0x00, 0x74, 0x0a, 0x83, 0x7f, 0x34, 0x00, 0x0f, 0x84,
							0xFF, 0xff, 0xff, 0xff, 0x8d},
						Value = new byte[] {
							0x8b, 0x07, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
							0x90, 0x90, 0x90, 0x90, 0x8d} }
					},
					// 4C89F1           mov         rcx,r14
					// BA01000000       mov         edx,1
					// 41B80F000010     mov         r8d,01000000F
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
					// 680F000010       push        01000000F
					// 6A01             push        1
					// FF75DC           push        d,[ebp][-024]
					// FF158CB9731D     call        RegNotifyChangeKeyValue
					// 85C0             test        eax,eax
					// 7422             jz         .014C680CF
					{ "RegNotifyChangeKeyValue (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] { 0x01, 0x50, 0x68, 0x0F, 0x00, 0x00, 0x10, 0x6a, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x15 },
						Value = new byte[] {0x01, 0x50, 0x68, 0x0F, 0x00, 0x00, 0x00, 0x6a, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x15 } }
					},
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
					// 84C0             test        al,al
					// 741B             jz         .016009AC3; -> 1
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
					{ "TerminateProcess (x86)", new BinaryDescriptor { 
						ArchType = ArchTypeE.x86,
						Key = new byte[] {
							0x84, 0xc0, 0x74, 0x1b, 0x8a, 0x85, 0xFF, 0xFF, 0xFF, 0xff, 0x88, 0x85, 0xFF, 0xFF, 0xFF, 0xFF, 0x89,
							0xd9 },
						Value = new byte[] {
							0x90, 0x90, 0x90, 0x90, 0x8a, 0x85, 0xFF, 0xFF, 0xFF, 0xff, 0x88, 0x85, 0xFF, 0xFF, 0xFF, 0xFF, 0x89,
							0xd9 },
					} },
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
					// 4881ECB8000000		 sub         rsp,0000000B8
					// 4889CE				 mov         rsi,rcx
					// 488B05B6C3900C		 mov         rax,[00000001`8FB34040]
					// 4831E0				 xor         rax,rsp
					// 48898424B0000000		 mov         [rsp][0000000B0],rax
					// E8168CBEFF			 call       .00000001`82E108B0
					// 83F80C				 cmp         eax,0C
					// 0F8EB2010000			 jle        .00000001`83227E55
					// 48B8AAAAAAAAAAAAAAAA  mov         rax,AAAAAAAA`AAAAAAAA ;'кккккккк'
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
					// 83EC4C                sub         esp,04C
					// 89CE                  mov         esi,ecx
					// A14000781D            mov         eax,[01D780040]
					// 31E8                  xor         eax,ebp
					// 8945F0                mov         [ebp][-010],eax
					// E8DAAA02FF            call       .014D02D90
					// 83F80C                cmp         eax,00C
					// 8975A8                mov         [ebp][-058],esi
					// 7F24                  jg         .015CD82E2
					{ "VersionCheck (x86)", new BinaryDescriptor {
						ArchType = ArchTypeE.x86,
						Key = new byte [] {
							0x89, 0x45, 0xff, 0xe8, 0xff, 0xff, 0xff, 0xff, 0x83, 0xf8, 0x0C, 0x89, 0x75, 0xff, 0x7f, 0xFF},
						Value = new byte[] {
							0x89, 0x45, 0xff, 0xe8, 0xff, 0xff, 0xff, 0xff, 0x83, 0xf8, 0x01, 0x89, 0x75, 0xff, 0x7f, 0xFF
						} }
					},
					// Replace IDWriteFactory3 with IDWriteFactory
					{ "IDWriteFactory3", new BinaryDescriptor {
						Key = new byte [] {
							0xc3, 0x41, 0x1b, 0x9a, 0xbb, 0xd3, 0x6a, 0x46, 0x87, 0xfc, 0xfe, 0x67, 0x55, 0x6a, 0x3b, 0x65 },
						Value = new byte[] {
							0x5a, 0xee, 0x59, 0xb8, 0x38, 0xd8, 0x5b, 0x4b, 0xa2, 0xe8, 0x1a, 0xdc, 0x7d, 0x93, 0xdb, 0x48 } }
					},
				}
			},
			//Google Chrome stack
				new ReplaceItem
				{
					FileName = "chrome_proxy.exe",
					NullifyCertificateTable = true,
					Imports = new Dictionary<string,string> { { "kernel32.dll", "KERNEL64.dll" } },
					DelayImports = new Dictionary<string,string> { { "userenv.dll", "USERENX.dll" } },
					Binary = new Dictionary<string, BinaryDescriptor>
					{
						{ "bcrypt", new BinaryDescriptor {
							Key = Encoding.Unicode.GetBytes("bcryptprimitives"),
							Value = Encoding.Unicode.GetBytes("xcryptprimitives") }
						},
						{ "RtlGetDevice", new BinaryDescriptor {
							Key = new byte[] {
								0x56, 0x57, 0x48, 0x83, 0xec, 0x38, 0x48, 0x8b, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x31, 0xe0, 0x48, 0x89,
								0x44, 0x24, 0x30, 0xc7, 0x44, 0x24, 0x2c, 0xff, 0xff, 0xff, 0xff, 0x48, 0x8d, 0x0d, 0xFF, 0xFF, 0xFF, 0x00,
								0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8d, 0x15, 0xff, 0xff, 0xff, 0x00, 0x48, 0x89, 0xc1, 0xff, 0x15,
								0xff, 0xff, 0xff, 0x00},
							Value = new byte[] {
								0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90}
						} }
					}
				},
				new ReplaceItem
				{
					FileName = "chrome.exe",
					NullifyCertificateTable = true,
					Imports = new Dictionary<string,string> { { "kernel32.dll", "KERNEL64.dll" }},
					DelayImports = new Dictionary<string,string> { { "userenv.dll", "USERENX.dll" } },
					Binary = new Dictionary<string, BinaryDescriptor>
					{
						{ "bcrypt", new BinaryDescriptor {
							Key = Encoding.Unicode.GetBytes("bcryptprimitives"),
							Value = Encoding.Unicode.GetBytes("xcryptprimitives"),
							ArchType = ArchTypeE.Both }
						},
						{ "TerminateProcess", new BinaryDescriptor {
							Key = new byte [] {
								0x75, 0x14, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xc1, 0xba, 0x62, 0x1b, 0x00, 0x00, 0xff, 0x15 },
							Value = new byte[] {
								0xeb, 0x14, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xc1, 0xba, 0x62, 0x1b, 0x00, 0x00, 0xff, 0x15},
							ArchType = ArchTypeE.Both }
						},
						{ "TerminateProcess (alt)", new BinaryDescriptor {
							Key = new byte [] {
								0x75, 0x31, 0xe8, 0xff, 0xff, 0xff, 0xff, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xc1, 0xba, 0x62,
								0x1b, 0x00, 0x00, 0xff, 0x15},
							Value = new byte[] {
								0xeb, 0x31, 0xe8, 0xff, 0xff, 0xff, 0xff, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xc1, 0xba, 0x62,
								0x1b, 0x00, 0x00, 0xff, 0x15},
							ArchType = ArchTypeE.Both }
						},

						/*
						(ELF) add
							00000001401976B8 | BA 621B0000                | mov edx, 0x1B62                                       | SBOX_FATALCLOSEHANDLES
							00000001401976BD | FF15 $$$$$$$$              | call qword ptr ds:[<TerminateProcess>]                |
						*/
						{ "SBOX_FATALCLOSEHANDLES x64", new BinaryDescriptor {
							Key = new byte [] {0xBA, 0x62, 0x1B, 0x00, 0x00, 0xFF, 0x15}, //
							Value = new byte[] {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90},
							ArchType = ArchTypeE.x64_only }
						},

						/*
						01309340 | 55               | push ebp                                                                                                                   |
						01309341 | 89E5             | mov ebp,esp                                                                                                                |
						01309343 | 53               | push ebx                                                                                                                   |
						01309344 | 57               | push edi                                                                                                                   |
						01309345 | 56               | push esi                                                                                                                   |
						01309346 | 83EC 18          | sub esp,18								<< sub esp, 0x78                                                                 |
						01309349 | 89D6             | mov esi,edx                                                                                                                |
						0130934B | 89CF             | mov edi,ecx                                                                                                                |
						0130934D | A1 40F03901      | mov eax,dword ptr ds:[139F040]                                                                                             |
						01309352 | 31E8             | xor eax,ebp                                                                                                                |
						01309354 | 8945 F0          | mov dword ptr ss:[ebp-10],eax                                                                                              |
						01309357 | 66:0F76C0        | pcmpeqd xmm0,xmm0                                                                                                          |
						0130935B | 8D45 E0          | lea eax,dword ptr ss:[ebp-20]             << lea eax, ss:[ebp-0x60]                                                        |
						0130935E | F3:0F7F00        | movdqu xmmword ptr ds:[eax],xmm0                                                                                           |
						01309362 | 8D5D DC          | lea ebx,dword ptr ss:[ebp-24]                                                                                              |
						01309365 | C703 FFFFFFFF    | mov dword ptr ds:[ebx],FFFFFFFF                                                                                            |
						0130936B | 53               | push ebx                                                                                                                   |
						0130936C | 6A 10            | push 10                                   << push 0x20                                                                     |
						0130936E | 50               | push eax                                                                                                                   |
						0130936F | FF71 04          | push dword ptr ds:[ecx+4]                                                                                                  |
						01309372 | FF71 10          | push dword ptr ds:[ecx+10]                                                                                                 |
						01309375 | FF15 44A73901    | call dword ptr ds:[<ReadProcessMemory>]                                                                                    |
						0130937B | 85C0             | test eax,eax                                                                                                               |
						0130937D | 0F95C0           | setne al                                                                                                                   |
						01309380 | 833B 10          | cmp dword ptr ds:[ebx],10                 << cmp dword ptr ds:[ebx], 0x20                                                  |
						01309383 | 0F94C3           | sete bl                                                                                                                    |
						01309386 | 20C3             | and bl,al                                                                                                                  |
						01309388 | 80FB 01          | cmp bl,1                                                                                                                   |
						0130938B | 75 27            | jne chrome.13093B4                                                                                                         |
						0130938D | 807D E0 E9       | cmp byte ptr ss:[ebp-20],E9               << cmp byte ptr ss:[ebp-0x60], 0xE9                                              |
						01309391 | 75 18            | jne chrome.13093AB                                                                                                         |
						01309393 | 8B45 08          | mov eax,dword ptr ss:[ebp+8]                                                                                               |
						01309396 | 8B4D E1          | mov ecx,dword ptr ss:[ebp-1F]                                                                                              |
						01309399 | 8B57 04          | mov edx,dword ptr ds:[edi+4]                                                                                               | 
						0130939C | 29C1             | sub ecx,eax                                                                                                                |
						0130939E | 01D1             | add ecx,edx                                                                                                                |
						013093A0 | 894D E1          | mov dword ptr ss:[ebp-1F],ecx                                                                                              |
						013093A3 | 29D0             | sub eax,edx                                                                                                                |
						013093A5 | 83C0 13          | add eax,13                                                                                                                 |
						013093A8 | 8947 18          | mov dword ptr ds:[edi+18],eax             << jmp 0x!!!!!!!!!!!                                                             |
						013093AB | F3:0F6F45 E0     | movdqu xmm0,xmmword ptr ss:[ebp-20]                                                                                        |
						013093B0 | F3:0F7F06        | movdqu xmmword ptr ds:[esi],xmm0                                                                                           |
						013093B4 | 8B4D F0          | mov ecx,dword ptr ss:[ebp-10]                                                                                              |
						013093B7 | 31E9             | xor ecx,ebp                                                                                                                |
						013093B9 | E8 9707FDFF      | call chrome.12D9B55                                                                                                        |
						013093BE | 89D8             | mov eax,ebx                                                                                                                |
						013093C0 | 83C4 18          | add esp,18                                << add esp, 0x78                                                                 |
						013093C3 | 5E               | pop esi                                                                                                                    |
						013093C4 | 5F               | pop edi                                                                                                                    |
						013093C5 | 5B               | pop ebx                                                                                                                    |
						013093C6 | 5D               | pop ebp                                                                                                                    |
						013093C7 | C3               | ret                                                                                                                        |
						...
						0x!!!!!!!!!!! | 
						0135E7C3 | F3:0F6F45 A0     | movdqu xmm0,xmmword ptr ss:[ebp-60]                                                                                        |
						0135E7C8 | F3:0F7F06        | movdqu xmmword ptr ds:[esi],xmm0                                                                                           |
						0135E7CC | F3:0F6F45 B0     | movdqu xmm0,xmmword ptr ss:[ebp-50]                                                                                        |
						0135E7D1 | F3:0F7F46 10     | movdqu xmmword ptr ds:[esi+10],xmm0                                                                                        |
						0135E7D6 | E9 FCABFAFF      | jmp chrome.013093B4                                                                                                        |

						------
						{ "SANDBOX FIX x86", new BinaryDescriptor {
							Key = new byte [] {}, //
							Value = new byte[] {},
							ArchType = ArchTypeE.x86_only }
						},
						*/
					},
				},
				new ReplaceItem
				{
					FileName = "chrome_elf.dll",
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
					FileName = "chrome_pwa_launcher.exe",
					NullifyCertificateTable = true,
					Imports = new Dictionary<string,string> { { "kernel32.dll", "KERNEL64.dll" } },
					DelayImports = new Dictionary<string,string>(),
					Binary = new Dictionary<string, BinaryDescriptor>
					{
						{ "bcrypt", new BinaryDescriptor {
							Key = Encoding.Unicode.GetBytes("bcryptprimitives"),
							Value = Encoding.Unicode.GetBytes("xcryptprimitives") }
						},
						{ "RtlGetDevice", new BinaryDescriptor {
							Key = new byte[] {
								0x56, 0x57, 0x48, 0x83, 0xec, 0x38, 0x48, 0x8b, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x31, 0xe0, 0x48, 0x89,
								0x44, 0x24, 0x30, 0xc7, 0x44, 0x24, 0x2c, 0xFF, 0xFF, 0xFF, 0xff, 0x48, 0x8d, 0x0d, 0xFF, 0xFF, 0xFF, 0x00,
								0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8d, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xc1, 0xFF},
							Value = new byte[] {
								0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90}
						} }
					}
				},
				new ReplaceItem
				{
					FileName = "chrome.dll",
					NullifyCertificateTable = true,
					Imports = new Dictionary<string,string> { { "kernel32.dll", "KERNEL64.dll" },  { "userenv.dll", "USERENX.dll" }, { "winhttp.dll", "WINXTTP.dll"},  { "netapi32.dll", "NETAPI64.dll"}},
					DelayImports = new Dictionary<string,string>
					{
						{ "user32.dll", "USER64.dll" },
						{ "mfplat.dll", "XFPlat.DLL" },
						{ "userenv.dll", "USERENX.dll" },
						{ "netapi32.dll", "NETAPI64.dll"},
						{ "winhttp.dll", "WINXTTP.dll"},
						{ "bcrypt.dll", "xcrypt.dll"}, //(RETURNED)
						{ "bcryptprimitives.dll", "XCRYPTPRIMITIVES.dll"}, //(ELF) add
					},
					Binary = new Dictionary<string, BinaryDescriptor>
					{
						{ "bcrypt", new BinaryDescriptor {
							Key = Encoding.Unicode.GetBytes("bcryptprimitives"),
							Value = Encoding.Unicode.GetBytes("xcryptprimitives"),
							ArchType = ArchTypeE.Both }
						},
						{ "edge/ntp", new BinaryDescriptor {
							Key = Encoding.ASCII.GetBytes("https://ntp.msn.com/edge/ntp\0"),
							Value = Encoding.ASCII.GetBytes("about:blank\0\0\0\0\0\0\0"),
							UpdateType = UpdateType.NtpOnly,
							ArchType = ArchTypeE.Both
						}},
						{ "edge/ntp-2", new BinaryDescriptor {
							Key = Encoding.ASCII.GetBytes("https://ntp.msn.com/edge/ntp?\0"),
							Value = Encoding.ASCII.GetBytes("about:blank\0\0\0\0\0\0\0"),
							UpdateType = UpdateType.NtpOnly,
							ArchType = ArchTypeE.Both
						}},
						{ "local-ntp", new BinaryDescriptor {
							Key = Encoding.ASCII.GetBytes("chrome-search://local-ntp/local-ntp.html\0"),
							Value = Encoding.ASCII.GetBytes("about:blank\0\0\0\0\0\0\0"),
							UpdateType = UpdateType.NtpOnly,
							ArchType = ArchTypeE.Both
						}},
						{ "RtlGetDevice", new BinaryDescriptor {
							Key = new byte [] {
								0x56, 0x48, 0x83, 0xec, 0x30, 0x48, 0x8b, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x31, 0xE0, 0x48, 0x89,
								0x44, 0x24, 0x28, 0xC7, 0x44, 0x24, 0x24, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8d, 0x0D, 0xFF, 0xFF, 0xFF,
								0xFF, 0xFF, 0x15, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8d, 0x15, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x89, 0xC1,
								0xFF, 0x15, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x85, 0xc0, 0x74, 0xFF, 0x48, 0x8d, 0x74, 0x24, 0x24, 0x31,
								0xc9},
							Value = new byte[] {
								0x31, 0xc0, 0xc3, 0x90, 0x90 },
							ArchType = ArchTypeE.Both }
						},
						{ "DuplicateHandle", new BinaryDescriptor {
							Key = new byte [] { 0x30, 0xc1, 0x0f, 0x84, 0xFF, 0xFF, 0x00, 0x00, 0x4C, 0x8B, 0xff, 0x24, 0xC0, 0x00 },
							Value = new byte[] {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x4C, 0x8B, 0xff, 0x24, 0xC0, 0x00 },
							ArchType = ArchTypeE.Both }
						},
						{ "RegNotifyChangeKeyValue", new BinaryDescriptor {
							Key = new byte [] { 0x41, 0xB8, 0x0F, 0x00, 0x00, 0x10, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0xFF, 0x85 },
							Value = new byte[] {0x41, 0xB8, 0x0F, 0x00, 0x00, 0x00, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0xFF, 0x85 },
							ArchType = ArchTypeE.Both }
						},
						{ "TerminateProcess", new BinaryDescriptor {
							Key = new byte [] { 0x84, 0xFF, 0x75, 0x14, 0xff, 0x15, 0xFF, 0xff, 0xff, 0xff, 0x48, 0x89, 0xc1, 0xba, 0x5e, 0x1b, 0x00, 0x00 },
							Value = new byte[] {0x84, 0xff, 0xeb, 0x14, 0xff, 0x15, 0xff, 0xff, 0xff, 0xff, 0x48, 0x89, 0xc1, 0xba, 0x5e, 0x1b, 0x00, 0x00 },
							ArchType = ArchTypeE.Both }
						},
						{ "TerminateProcess-a", new BinaryDescriptor {
							Key = new byte [] { 0x48, 0x85, 0xc9, 0x74, 0x12, 0x48, 0x8d, 0x15, 0xFF, 0xFF, 0xFF, 0x04, 0x48, 0x83, 0xc4, 0x28, 0x48, 0xff },
							Value = new byte[] {0x48, 0x85, 0xc9, 0xeb, 0x12, 0x48, 0x8d, 0x15, 0xff, 0xFf, 0xff, 0x04, 0x48, 0x83, 0xc4, 0x28, 0x48, 0xff },
							ArchType = ArchTypeE.Both }
						},
						{ "TerminateProcess-b", new BinaryDescriptor {
							Key = new byte [] { 0x08, 0x00, 0x00, 0xb9, 0x00, 0x09, 0x00, 0x00, 0x0f, 0x45, 0xc8, 0x89, 0x8c, 0x24 },
							Value = new byte[] {0x08, 0x00, 0x00, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x45, 0xc8, 0x89, 0x8c, 0x24 },
							ArchType = ArchTypeE.Both }
						},
						{ "TerminateProcess-c", new BinaryDescriptor {
							Key = new byte [] {
								0x48, 0x83, 0xbc, 0x24, 0x28, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x84, 0x19, 0x01, 0x00, 0x00, 0x4c, 0x8b,
								0xac, 0x24},
							Value = new byte[] {
								0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x4C, 0x8B,
								0xAC, 0x24
							},
							ArchType = ArchTypeE.Both }
						},
						{ "TerminateProcess-c(alt)", new BinaryDescriptor {
							Key = new byte [] {
								0x48, 0x83, 0xbc, 0x24, 0xff, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x84, 0xff, 0xff, 0x00, 0x00, 0x48, 0x89,
								0xbc, 0x24, 0x98, 0x00, 0x00, 0x8b, 0xb4, 0x24},
							Value = new byte[] {
								0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x48, 0x89,
								0xbC, 0x24, 0x98, 0x00, 0x00, 0x8b, 0xb4, 0x24
							},
							ArchType = ArchTypeE.Both }
						},
						{ "TerminateProcess-c(alt2)", new BinaryDescriptor {
							Key = new byte [] {
								0x48, 0x83, 0x39, 0x00, 0x0f, 0x84, 0xff, 0xff, 0x00, 0x00, 0x44, 0x89, 0xc5, 0x49, 0x89, 0xd7, 0x48,
								0x8b, 0x72, 0x08},
							Value = new byte[] {
								0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x44, 0x89, 0xc5, 0x49, 0x89, 0xd7, 0x48,
								0x8b, 0x72, 0x08
							},
							ArchType = ArchTypeE.Both }
						},
						{ "interface", new BinaryDescriptor {
							Key = new byte [] { 0xc3, 0x41, 0x1b, 0x9a, 0xbb, 0xd3, 0x6a, 0x46, 0x87, 0xfc, 0xfe, 0x67, 0x55, 0x6a, 0x3b, 0x65 },
							Value = new byte[] {0x5a, 0xee, 0x59, 0xb8, 0x38, 0xd8, 0x5b, 0x4b, 0xa2, 0xe8, 0x1a, 0xdc, 0x7d, 0x93, 0xdb, 0x48 },
							ArchType = ArchTypeE.Both }
						},

						/*
						(ELF) add handle
							000007FEC09EC7B3 | 45:85F6                    | test r14d,r14d                                        |
							000007FEC09EC7B6 | 0F94C0                     | sete al                                               |
							000007FEC09EC7B9 | 85ED                       | test ebp,ebp                                          |
							000007FEC09EC7BB | 0F95C1                     | setne cl                                              |
							000007FEC09EC7BE | 30C1                       | xor cl,al                                             |
							000007FEC09EC7C0 | 0F84 $$$$$$$$              | je chrome.$$$$$$$$$$$                                 |
						*/
						{ "HANDLE x64", new BinaryDescriptor {
							Key = new byte [] {0x45, 0x85, 0xF6, 0x0F, 0x94, 0xC0, 0x85, 0xED, 0x0F, 0x95, 0xC1, 0x30, 0xC1, 0x0F, 0x84}, //
							Value = new byte[] {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,0x90, 0x90, 0x90},
							ArchType = ArchTypeE.x64_only}
						},

						/*
							127FDC98 | 85FF             | test edi,edi                                                                                                               |
							127FDC9A | 0F94C0           | sete al                                                                                                                    |
							127FDC9D | 837C24 04 00     | cmp dword ptr ss:[esp+4],0                                                                                                 |
							127FDCA2 | 0F95C1           | setne cl                                                                                                                   |
							127FDCA5 | 30C1             | xor cl,al                                                                                                                  |
							127FDCA7 | 0F84 $$$$$$$$    | je chrome.$$$$$$$$                                                                                                         |
						*/
						{ "HANDLE x86", new BinaryDescriptor {
							Key = new byte [] {0x85, 0xFF, 0x0F, 0x94, 0xC0, 0x83, 0x7C, 0x24, 0x04, 0x00, 0x0F, 0x95, 0xC1, 0x30, 0xC1, 0x0F, 
								0x84}, //
							Value = new byte[] {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
							0x90, 0x90, 0x90, 0x90, 0x90},
							ArchType = ArchTypeE.x86_only}
						},

							/*
						(ELF) add SBOX
							00000001401976B8 | BA 621B0000                | mov edx,1B62                                          |
							00000001401976BD | FF15 $$$$$$$$              | call qword ptr ds:[<TerminateProcess>]                |
						*/
						{ "SBOX_FATALCLOSEHANDLES x64", new BinaryDescriptor {
							Key = new byte [] {0xBA, 0x62, 0x1B, 0x00, 0x00, 0xFF, 0x15}, //
							Value = new byte[] {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90},
							ArchType = ArchTypeE.x64_only
							}
						},

						//(ELF) add WEBGPU2 interrupt
						{ "WEBGPU2 x64", new BinaryDescriptor {
							Key = new byte [] {0xF7, 0x84, 0x24, 0x48, 0x01, 0x00, 0x00, 0x40, 0x00, 0x10, 0x00, 0x0F, 0x95, 0xC0, 0x48, 0x85,
								0xED, 0x0F, 0x94, 0xC1, 0x20, 0xC1, 0x80, 0xF9, 0x01, 0x0F, 0x84, 0x4B, 0x01, 0x00, 0x00}, //
							Value = new byte[] {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
								0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90},
							ArchType = ArchTypeE.x64_only}
						},
					},
				},
				new ReplaceItem
				{
					FileName = "dxcompiler.dll",
					NullifyCertificateTable = true,
					Imports = new Dictionary<string,string> { },
					DelayImports = new Dictionary<string,string>(),
					Binary = new Dictionary<string, BinaryDescriptor>(),
				},
				new ReplaceItem
				{
					FileName = "dxil.dll",
					NullifyCertificateTable = true,
					Imports = new Dictionary<string,string> { },
					DelayImports = new Dictionary<string,string>(),
					Binary = new Dictionary<string, BinaryDescriptor>(),
				},
				new ReplaceItem
				{
					FileName = "libEGL.dll",
					NullifyCertificateTable = true,
					Imports = new Dictionary<string,string> { },
					DelayImports = new Dictionary<string,string>(),
					Binary = new Dictionary<string, BinaryDescriptor>(),
				},
				new ReplaceItem
				{
					FileName = "libGLESv2.dll",
					NullifyCertificateTable = true,
					Imports = new Dictionary<string,string> { },
					DelayImports = new Dictionary<string,string>(),
					Binary = new Dictionary<string, BinaryDescriptor>(),
				},
				new ReplaceItem
				{
					FileName = "optimization_guide_internal.dll",
					NullifyCertificateTable = true,
					Imports = new Dictionary<string,string> { },
					DelayImports = new Dictionary<string,string>(),
					Binary = new Dictionary<string, BinaryDescriptor>(),
				},
				new ReplaceItem
				{
					FileName = "vk_swiftshader.dll",
					NullifyCertificateTable = true,
					Imports = new Dictionary<string,string> { },
					DelayImports = new Dictionary<string,string>(),
					Binary = new Dictionary<string, BinaryDescriptor>(),
				},
				new ReplaceItem
				{
					FileName = "vulkan-1.dll",
					NullifyCertificateTable = true,
					Imports = new Dictionary<string,string> { },
					DelayImports = new Dictionary<string,string>(),
					Binary = new Dictionary<string, BinaryDescriptor>(),
				},
			}; //end stack
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
			Console.WriteLine("     Updated {0} of {1} bytes at 0x{2:X}", updatedBytes, replacement.Length, fileOffset);
		}
	}
}
