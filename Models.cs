using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Edge.Patcher
{
	internal class ReplaceItem
	{
		public string FileName { get; set; }
		public bool NullifyCertificateTable { get; set; }
		public Dictionary<string, string> Imports { get; set; }
		public Dictionary<string, string> DelayImports { get; set; }
		public Dictionary<string, BinaryDescriptor> Binary { get; set; }
	}

	internal class BinaryDescriptor
	{
		public BinaryDescriptor()
		{
			UpdateType = UpdateType.References;
			ArchType = ArchTypeE.Both;
		}

		public byte[] Key { get; set; }
		public byte[] Value { get; set; }
		public UpdateType UpdateType { get; set; }
		public ArchTypeE ArchType { get; set; }
	}

	[Flags]
	internal enum UpdateType
	{
		None = 0,
		NtpOnly = 1,
		References = 2,
		All = 3,
	}

	internal enum ArchTypeE
	{
		Both = 0,
		x86 = 1,
		x64 = 2,
	}
}
