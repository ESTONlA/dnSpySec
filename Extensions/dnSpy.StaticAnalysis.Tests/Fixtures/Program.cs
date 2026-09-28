using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

// These functions are IL fixtures, never invoked by the tests or analyzer.
static class Program {
	[ModuleInitializer]
	public static void Initialize() => throw new InvalidOperationException("Sample module initializer executed");
	static Program() => throw new InvalidOperationException("Sample static constructor executed");
	static void Main() => throw new InvalidOperationException("Sample entry point executed");
	public static string Base64() => Encoding.UTF8.GetString(Convert.FromBase64String("aHR0cHM6Ly9leGFtcGxlLm9yZy9zdGF0aWM="));
	static int runtimeValue;
	public static string DecodeAfterUnrelated() { runtimeValue = Environment.TickCount; return Encoding.UTF8.GetString(Convert.FromBase64String("aHR0cHM6Ly9leGFtcGxlLm9yZy9zdGF0aWM=")); }
	public static string Webhook() => Encoding.UTF8.GetString(Convert.FromBase64String("aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTIzNDU2Nzg5MDEyMzQ1Njc4L1NFQ1JFVF9UT0tFTg=="));
	public static string Bytes() => Encoding.UTF8.GetString(new byte[] { 104, 101, 108, 108, 111 });
	public static string EncodeThenXor() => XorHelper(Encoding.UTF8.GetBytes("kfool"), 3);
	public static string Hex() => Encoding.UTF8.GetString(Convert.FromHexString("68747470733a2f2f6578616d706c652e6f7267"));
	public static string Reverse() { var chars = "elpmaxe".ToCharArray(); Array.Reverse(chars); return new string(chars); }
	public static string Xor() => XorHelper(new byte[] { 107, 102, 111, 111, 108 }, 3);
	static string XorHelper(byte[] bytes, int key) { for (int i = 0; i < bytes.Length; i++) bytes[i] = (byte)(bytes[i] ^ key); return Encoding.UTF8.GetString(bytes); }
	public static string Rot() { var chars = "uryyb".ToCharArray(); for (int i = 0; i < chars.Length; i++) chars[i] = (char)('a' + (chars[i] - 'a' + 13) % 26); return new string(chars); }
	public static string Concat() => string.Concat(Prefix(), "example.org");
	static string Prefix() => "https://";
	public static string ForbiddenAfterDecode() { var value = Base64(); NeverCall(); return value; }
	static void NeverCall() { File.WriteAllText(Path.Combine(Path.GetTempPath(), "dnspy-static-fixture-must-not-run.txt"), "This method must never run"); throw new InvalidOperationException("Sample helper executed"); }
	public static void AesSettings() { using var aes = Aes.Create(); aes.Mode = CipherMode.CBC; aes.Key = Convert.FromBase64String("MDEyMzQ1Njc4OWFiY2RlZg=="); aes.IV = Convert.FromHexString("30313233343536373839616263646566"); }
}
