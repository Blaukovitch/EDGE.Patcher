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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace Edge.Patcher
{
	class Program
	{
		static void Main(string[] args)
		{
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
			bool without_scan_apims_libs = false;
			var updateTypeArg = args.Skip(1).FirstOrDefault();
			if (string.Equals(updateTypeArg, "-all", StringComparison.OrdinalIgnoreCase))
			{
				updateType = UpdateType.All;
			}
			else if (string.Equals(updateTypeArg, "-ntp", StringComparison.OrdinalIgnoreCase))
			{
				updateType = UpdateType.NtpOnly;
			}

			if (string.Equals(updateTypeArg, "-wo", StringComparison.OrdinalIgnoreCase))
			{
				without_scan_apims_libs = true;
			}

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

					var archType = pe.Is32BitHeader ? ArchTypeE.x86_only : ArchTypeE.x64_only;
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

			//(ELF) add
			if (!without_scan_apims_libs)
            {
                Verify_APIMSLibs_status(rootFolder, extensions);
            }
        }

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

		private static readonly ReplaceItem[] files = new ReplaceItem[]
		{ 
			//Microsoft EDGE stack
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
						Value = Encoding.Unicode.GetBytes("xcryptprimitives"),
						ArchType = ArchTypeE.Both
						}
					},
					{ "RtlGetDevice", new BinaryDescriptor {
						Key = new byte[] {
							0x56, 0x57, 0x48, 0x83, 0xec, 0x38, 0x48, 0x8b, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x31, 0xe0, 0x48, 0x89,
							0x44, 0x24, 0x30, 0xc7, 0x44, 0x24, 0x2c, 0xff, 0xff, 0xff, 0xff, 0x48, 0x8d, 0x0d, 0xFF, 0xFF, 0xFF, 0x00,
							0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8d, 0x15, 0xff, 0xff, 0xff, 0x00, 0x48, 0x89, 0xc1, 0xff, 0x15,
							0xff, 0xff, 0xff, 0x00},
						Value = new byte[] {
							0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90},
						ArchType = ArchTypeE.Both
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
						Value = Encoding.Unicode.GetBytes("xcryptprimitives"),
						ArchType = ArchTypeE.Both
					}
			        },
			        { "RtlGetDevice", new BinaryDescriptor {
			            Key = new byte [] { 
			                0x56, 0x48, 0x83, 0xec, 0x30, 0x48, 0x8b, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x31, 0xE0, 0x48, 0x89, 0x44,
			                0x24, 0x28, 0xC7, 0x44, 0x24, 0x24, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8D, 0x0D, 0xFF, 0xFF, 0xFF, 0x00, 0xFF,
			                0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8D, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xC1}, 
			            Value = new byte[] {
			                0x31, 0xc0, 0xc3, 0x90, 0x90},
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
			            Value = Encoding.Unicode.GetBytes("xcryptprimitives"),
						ArchType = ArchTypeE.Both }
			        },
			        { "binary-1", new BinaryDescriptor {
			            Key = new byte [] { 
			                0x4c, 0x89, 0xe8, 0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0xFc, 0xFF, 0xFF, 0xFF, 0x48, 0x21, 0xc8, 0xb9, 0x01,
			                0x00, 0x00, 0x00}, 
			            Value = new byte[] {
			                0x4c, 0x89, 0xe8, 0x48, 0xc7, 0xc1, 0x00, 0x00, 0x00, 0xfe, 0x90, 0x90, 0x90},
						ArchType = ArchTypeE.Both }
			        },
			        { "binary-2", new BinaryDescriptor {
			            Key = new byte [] { 
			                0x8a, 0x07, 0x49, 0xbd, 0x00, 0x00, 0x00, 0x00, 0xFc, 0xFF, 0xFF, 0xFF, 0x4c, 0x23, 0x6c, 0x24, 0xFF, 0x4c}, 
			            Value = new byte[] {
			                0x8a, 0x07, 0x49, 0xc7, 0xc5, 0x00, 0x00, 0x00, 0xfe, 0x90, 0x90, 0x90},
						ArchType = ArchTypeE.Both }
			        },
			        { "RtlGetDevice", new BinaryDescriptor {
			            Key = new byte [] { 
			                0x56, 0x57, 0x48, 0x83, 0xec, 0x38, 0x48, 0x8b, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x31, 0xE0, 0x48, 0x89,
			                0x44, 0x24, 0x30, 0xC7, 0x44, 0x24, 0x2c, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8D, 0x0D, 0xFF, 0xFF, 0xFF, 0x00,
			                0xFF, 0x15, 0xFF, 0xFF, 0xFF}, 
			            Value = new byte[] {
			                0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90},
						ArchType = ArchTypeE.Both }
			        },
			        { "binary-3", new BinaryDescriptor {
			            Key = new byte [] { 
			                0xd7, 0x00, 0x00, 0x00, 0x48, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xc7, 0x44, 0x24}, 
			            Value = new byte[] {
			                0xd7, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc6, 0x00, 0x00, 0x00, 0x02, 0x90, 0x90, 0x90},
						ArchType = ArchTypeE.Both }
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
			            Value = Encoding.Unicode.GetBytes("xcryptprimitives"),
						ArchType = ArchTypeE.Both }
			        },
			        { "RtlGetDevice", new BinaryDescriptor {
			            Key = new byte [] { 
			                0x56, 0x57, 0x48, 0x83, 0xec, 0x38, 0x48, 0x8b, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x31, 0xE0, 0x48, 0x89,
			                0x44, 0x24, 0x30, 0xC7, 0x44, 0x24, 0x2c, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8D, 0x0D, 0xFF, 0xFF, 0xFF, 0x00,
			                0xFF, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8D, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xC1}, 
			            Value = new byte[] {
			                0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90},
						ArchType = ArchTypeE.Both }
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
			            Value = Encoding.Unicode.GetBytes("xcryptprimitives"),
						ArchType = ArchTypeE.Both }
			        },
			        { "RtlGetDevice", new BinaryDescriptor {
			            Key = new byte [] { 
			                0x56, 0x57, 0x48, 0x83, 0xec, 0x38, 0x48, 0x8b, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x31, 0xE0, 0x48, 0x89,
			                0x44, 0x24, 0x30, 0xC7, 0x44, 0x24, 0x2c, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8D, 0x0D, 0xFF, 0xFF, 0xFF, 0x00,
			                0xFF, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8D, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xC1}, 
			            Value = new byte[] {
			                0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90},
						ArchType = ArchTypeE.Both }
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
					//{ "bcrypt", new BinaryDescriptor { 
					//    Key = Encoding.Unicode.GetBytes("bcryptprimitives"), 
					//    Value = Encoding.Unicode.GetBytes("xcryptprimitives") }
					//},
					//{ "RtlGetDevice", new BinaryDescriptor { 
					//    Key = new byte[] { 
					//        0x48, 0x8d, 0x0d, 0xFF, 0xFF, 0xFF, 0x00, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8d, 0x15, 0xFF, 0xFF, 
					//        0xFF, 0x00, 0x48, 0x89, 0xc1, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x3a, 0x31, 0xf6,
					//        0x48, 0x8d, 0x7c, 0x24, 0x2c, 0x31, 0xc9, 0x48, 0x89, 0xfa, 0x45, 0x31, 0xc0, 0xff, 0x15, 0xFF, 0xFF, 0xFF,
					//        0x00, 0x8b, 0x07, 0x83, 0xf8, 0x03, 0x75, 0x16},
					//    Value = new byte[] {
					//        0x48, 0x31, 0xc0, 0x48, 0x89, 0xc6, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
					//        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
					//        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
					//        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}
					//} }
			    }
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
			            Value = Encoding.Unicode.GetBytes("xcryptprimitives"),
						ArchType = ArchTypeE.Both }
			        },
			        { "RtlGetDevice", new BinaryDescriptor { 
			            Key = new byte[] { 
			                0x56, 0x57, 0x48, 0x83, 0xec, 0x38, 0x48, 0x8b, 0x05, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x31, 0xe0, 0x48, 0x89, 
			                0x44, 0x24, 0x30, 0xc7, 0x44, 0x24, 0x2c, 0xFF, 0xFF, 0xFF, 0xff, 0x48, 0x8d, 0x0d, 0xFF, 0xFF, 0xFF, 0x00, 
			                0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8d, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xc1, 0xFF},
			            Value = new byte[] { 
			                0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90},
						ArchType = ArchTypeE.Both
					} }
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
			            Value = Encoding.Unicode.GetBytes("xcryptprimitives"),
						ArchType = ArchTypeE.Both }
			        },
			        { "RtlGetDevice", new BinaryDescriptor { 
			            Key = new byte[] { 
			                0x56, 0x57, 0x48, 0x83, 0xec, 0x38, 0x48, 0x8b, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x31, 0xe0, 0x48, 0x89, 
			                0x44, 0x24, 0x30, 0xc7, 0x44, 0x24, 0x2c, 0xFF, 0xFF, 0xFF, 0xff, 0x48, 0x8d, 0x0d, 0xFF, 0xFF, 0xFF, 0x00, 
			                0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8d, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xc1, 0xFF},
			            Value = new byte[] { 
			                0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90},
						ArchType = ArchTypeE.Both
					} }
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
			            Value = Encoding.Unicode.GetBytes("xcryptprimitives"),
						ArchType = ArchTypeE.Both }
			        },
			        { "RtlGetDevice", new BinaryDescriptor { 
			            Key = new byte[] { 
			                0x56, 0x48, 0x83, 0xec, 0x30, 0x48, 0x8b, 0x05, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x31, 0xe0, 0x48, 0x89, 0x44,
			                0x24, 0xFF, 0xc7, 0x44, 0x24, 0x24, 0xFF, 0xFF, 0xFF, 0xff, 0x48, 0x8d, 0x0d, 0xFF, 0xFF, 0xFF, 0x00, 0xff,
			                0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8d, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xc1, 0xFF},
			            Value = new byte[] { 
			                0x31, 0xc0, 0xc3, 0x90, 0x90},
						ArchType = ArchTypeE.Both
					} },
			        { "TerminateProcess", new BinaryDescriptor { 
			            Key = new byte[] {
                            0x40, 0x84, 0xed, 0x75, 0x14, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xC1, 0xBA, 0x62, 0x1b, 0x00, 0x00 },
                        Value = new byte[] {
                            0x90, 0x90, 0x90, 0xeb, 0x14, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xC1, 0xBA, 0x62, 0x1b, 0x00, 0x00 },
						ArchType = ArchTypeE.Both
					} },
			        { "TerminateProcess (alt)", new BinaryDescriptor { 
			            Key = new byte[] {
                            0x84, 0xc0, 0x75, 0x31, 0xe8, 0xff, 0xff, 0xff, 0xff, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xC1,
                            0xBA, 0x62, 0x1b, 0x00, 0x00 },
                        Value = new byte[] {
                            0x90, 0x90, 0xeb, 0x31, 0xe8, 0xff, 0xff, 0xff, 0xff, 0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xC1,
                            0xBA, 0x62, 0x1b, 0x00, 0x00 },
						ArchType = ArchTypeE.Both
					} }
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
			            Value = Encoding.Unicode.GetBytes("xcryptprimitives"),
						ArchType = ArchTypeE.Both }
			        },
			        { "RtlGetDevice", new BinaryDescriptor { 
			            Key = new byte[] { 
			                0x56, 0x57, 0x48, 0x83, 0xec, 0x38, 0x48, 0x8b, 0x05, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x31, 0xe0, 0x48, 0x89, 
			                0x44, 0x24, 0x30, 0xc7, 0x44, 0x24, 0x2c, 0xFF, 0xFF, 0xFF, 0xff, 0x48, 0x8d, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 
			                0xff, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8d, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89, 0xc1, 0xFF},
			            Value = new byte[] { 
			                0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90},
						ArchType = ArchTypeE.Both
					} },
			    }
			},
			new ReplaceItem 
			{ 
			    FileName = "pwahelper.exe",
			    NullifyCertificateTable = true,
			    Imports = new Dictionary<string,string> { { "kernel32.dll", "KERNEL64.dll" } },
			    DelayImports = new Dictionary<string,string>(),
			    Binary = new Dictionary<string, BinaryDescriptor>(),
			},
			new ReplaceItem 
			{ 
			    FileName = "dual_engine_adapter_x64.dll",
			    NullifyCertificateTable = true,
			    Imports = new Dictionary<string,string> { { "kernel32.dll", "KERNEL64.dll" } },
			    DelayImports = new Dictionary<string,string>(),
			    Binary = new Dictionary<string, BinaryDescriptor>(),
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
			            Value = Encoding.Unicode.GetBytes("xcryptprimitives"),
						ArchType = ArchTypeE.Both}
			        },
			        { "RtlGetDevice", new BinaryDescriptor {
			            Key = new byte [] { 
			                0x56, 0x57, 0x48, 0x83, 0xEC, 0x38, 0x48, 0x8B, 0x05, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x31, 0xE0, 0x48,
			                0x89, 0x44, 0x24, 0x30, 0xC7, 0x44, 0x24, 0x2C, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8D, 0x0D, 0xFF, 0xFF,
			                0xFf, 0x00, 0xFF, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8D, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89,
			                0xC1, 0xFF, 0x15, 0xFF, 0xFF, 0xff, 0x00}, 
			            Value = new byte[] {
			                0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90 },
						ArchType = ArchTypeE.Both }
			        },
			    }
			},
			new ReplaceItem 
			{ 
			    FileName = "embeddedbrowserwebview.dll",
			    NullifyCertificateTable = true,
			    Imports = new Dictionary<string,string> { { "kernel32.dll", "KERNEL64.dll" } },
			    DelayImports = new Dictionary<string,string>(),
			    Binary = new Dictionary<string, BinaryDescriptor> 
			    { 
			        { "bcrypt", new BinaryDescriptor { 
			            Key = Encoding.Unicode.GetBytes("bcryptprimitives"), 
			            Value = Encoding.Unicode.GetBytes("xcryptprimitives"),
						ArchType = ArchTypeE.Both }
			        },
			        { "RtlGetDevice", new BinaryDescriptor {
			            Key = new byte [] { 
			                0x56, 0x57, 0x48, 0x83, 0xEC, 0x38, 0x48, 0x8B, 0x05, 0xFF, 0xff, 0xFF, 0x00, 0x48, 0x31, 0xE0, 0x48,
			                0x89, 0x44, 0x24, 0x30, 0xC7, 0x44, 0x24, 0x2C, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8D, 0x0D, 0xFF, 0xFF,
			                0xFF, 0x00, 0xFF, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x8D, 0x15, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x89,
			                0xC1, 0xFF, 0x15, 0xFF, 0xFF, 0xFF, 0x00}, 
			            Value = new byte[] {
			                0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90 },
						ArchType = ArchTypeE.Both }
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
					//{ "bcrypt.dll", "xcrypt.dll"}, //(ELF)fix - not needed!
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
					//{ "bcrypt.dll", "xcrypt.dll"}, //(ELF)fix - not needed!
					{ "bcryptprimitives.dll", "XCRYPTPRIMITIVES.dll"}, //(ELF)instead bcrypt.dll
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
	}
}
