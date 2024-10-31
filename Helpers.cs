using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace Edge.Patcher
{
	internal static class Helpers
	{
		internal static string GetRelativePath(this string fromPath, string toPath)
		{
			if (string.IsNullOrEmpty(fromPath))
			{
				throw new ArgumentNullException("fromPath");
			}

			if (string.IsNullOrEmpty(toPath))
			{
				throw new ArgumentNullException("toPath");
			}

			Uri fromUri = new Uri(AppendDirectorySeparatorChar(fromPath));
			Uri toUri = new Uri(AppendDirectorySeparatorChar(toPath));

			if (fromUri.Scheme != toUri.Scheme)
			{
				return toPath;
			}

			Uri relativeUri = fromUri.MakeRelativeUri(toUri);
			string relativePath = Uri.UnescapeDataString(relativeUri.ToString());

			if (string.Equals(toUri.Scheme, Uri.UriSchemeFile, StringComparison.OrdinalIgnoreCase))
			{
				relativePath = relativePath.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
			}

			return relativePath;
		}

		internal static string AppendDirectorySeparatorChar(string path)
		{
			// Append a slash only if the path is a directory and does not have a slash.
			if (!Path.HasExtension(path) &&
				!path.EndsWith(Path.DirectorySeparatorChar.ToString()))
			{
				return path + Path.DirectorySeparatorChar;
			}

			return path;
		}

		internal static bool ContainsFile(this Dictionary<string, string> data, string file)
		{
			if (data == null || data.Count == 0)
			{
				return false;
			}
			return data.Keys.Contains(file, StringComparer.OrdinalIgnoreCase) || data.Values.Contains(file, StringComparer.OrdinalIgnoreCase);
		}

		internal static int SearchBytes(this byte[] haystack, int startIndex, byte[] needle, int haystackSize)
		{
			var len = needle.Length;
			var limit = haystackSize - len;
			for (var i = startIndex; i <= limit; i++)
			{
				var k = 0;
				for (; k < len; k++)
				{
					if (needle[k] != haystack[i + k])
					{
						if (needle[k] != 0xFF)
						{
							break;
						}
					}
				}
				if (k == len)
				{
					return i;
				}
			}
			return -1;
		}
	}
}
