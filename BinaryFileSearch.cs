using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace Edge.Patcher
{
	internal class BinaryFileSearch
	{
		private string _fileName;
		private const int BUFFER_SIZE = 128 * 1024 * 1024;

		public BinaryFileSearch(string fileName)
		{
			_fileName = fileName;
		}

		public List<KeyValuePair<string, long>> FindReferences(Dictionary<string, BinaryDescriptor> items)
		{
			var results = new List<KeyValuePair<string, long>>();
			if (items == null || items.Count == 0)
			{
				return results.ToList();
			}

			using (FileStream fs = new FileStream(_fileName, FileMode.Open, FileAccess.Read))
			{
				using (BinaryReader reader = new BinaryReader(fs))
				{
					byte[] buffer = new byte[BUFFER_SIZE];
					int pos = 0;
					int maxLenth = items.Max(x => Math.Max(x.Value.Key.Length, x.Value.Key.Length));
					while (fs.Position < fs.Length)
					{
						int bufferSize = reader.Read(buffer, 0, BUFFER_SIZE);
						foreach (var item in items)
						{
							int index = 0;
							do
							{
								index = buffer.SearchBytes(index, item.Value.Key, bufferSize);
								if (index >= 0)
								{
									results.Add(new KeyValuePair<string, long>(item.Key, fs.Position - bufferSize + index));
									index += item.Value.Key.Length;
								}
							} while (index > 0);

							index = 0;
							do
							{
								index = buffer.SearchBytes(index, item.Value.Value, bufferSize);
								if (index >= 0)
								{
									results.Add(new KeyValuePair<string, long>(item.Key + " (Value)", fs.Position - bufferSize + index));
									index += item.Value.Value.Length;
								}
							} while (index > 0);
						}
						pos += BUFFER_SIZE - maxLenth;
						fs.Position = pos;
					}
				}
			}
			return results.ToList();
		}
	}
}
