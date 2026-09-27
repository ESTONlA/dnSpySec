using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

namespace dnSpy.SecurityAnalysis {
	// A deliberately narrow parser for PyInstaller PYZ TOCs: lists/tuples, names, integers, and references only.
	// It cannot construct or execute Python code objects.
	public sealed class SafePythonMarshalReader {
		readonly byte[] data;
		readonly CancellationToken cancellationToken;
		readonly List<object?> references = new List<object?>();
		int position;
		int values;

		public SafePythonMarshalReader(byte[] data, CancellationToken cancellationToken = default) {
			if (data.Length > AnalysisLimits.MaximumTocBytes) throw new InvalidDataException("Python marshal TOC too large.");
			this.data = data;
			this.cancellationToken = cancellationToken;
		}

		public object? Read() => ReadValue(0);

		object? ReadValue(int depth) {
			if ((values & 0x1FF) == 0) cancellationToken.ThrowIfCancellationRequested();
			if (depth > 16 || ++values > AnalysisLimits.MaximumArchiveEntries * 8) throw new InvalidDataException("Python marshal depth or value limit exceeded.");
			var tag = ReadByte();
			var referenced = (tag & 0x80) != 0;
			tag &= 0x7F;
			object? value;
			switch (tag) {
			case (byte)'[':
			case (byte)'(':
			case (byte)')': {
				var count = tag == (byte)')' ? ReadByte() : ReadInt32();
				if (count < 0 || count > AnalysisLimits.MaximumArchiveEntries || count > data.Length - position)
					throw new InvalidDataException("Invalid Python marshal sequence length.");
				var items = new object?[count];
				if (referenced) references.Add(items);
				for (int i = 0; i < count; i++) items[i] = ReadValue(depth + 1);
				return items;
			}
			case (byte)'z':
			case (byte)'Z': value = ReadString(ReadByte()); break;
			case (byte)'a':
			case (byte)'A':
			case (byte)'u':
			case (byte)'t': value = ReadString(ReadInt32()); break;
			case (byte)'i': value = ReadInt32(); break;
			case (byte)'I': value = ReadInt64(); break;
			case (byte)'N': value = null; break;
			case (byte)'r': {
				var index = ReadInt32();
				if (index < 0 || index >= references.Count) throw new InvalidDataException("Invalid Python marshal reference.");
				value = references[index];
				break;
			}
			default: throw new InvalidDataException("Unsupported Python marshal TOC tag: " + (char)tag);
			}
			if (referenced) references.Add(value);
			return value;
		}

		string ReadString(int length) {
			if (length < 0 || length > 4096 || length > data.Length - position) throw new InvalidDataException("Invalid Python marshal string length.");
			var value = Encoding.UTF8.GetString(data, position, length);
			position += length;
			return value;
		}

		byte ReadByte() {
			if (position >= data.Length) throw new EndOfStreamException();
			return data[position++];
		}

		int ReadInt32() {
			if (data.Length - position < 4) throw new EndOfStreamException();
			var value = data[position] | data[position + 1] << 8 | data[position + 2] << 16 | data[position + 3] << 24;
			position += 4;
			return value;
		}

		long ReadInt64() => (uint)ReadInt32() | (long)(uint)ReadInt32() << 32;
	}
}
