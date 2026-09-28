using System;
using System.IO;
using System.Threading;

// Host lifecycle tests only: no target parsing. Deep requests block; standard requests overflow.
using var input = new BinaryReader(Console.OpenStandardInput());
input.ReadInt32();
var block = input.ReadBoolean();
var bytes = input.ReadBytes(input.ReadInt32());
if (block) Thread.Sleep(Timeout.Infinite);
else {
	using var output = Console.OpenStandardOutput();
	var chunk = new byte[8192];
	for (int i = 0; i < 5000; i++) output.Write(chunk, 0, chunk.Length);
}
