using System;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace dnSpy.StaticAnalysis {
	public static class ConstantTransforms {
		public static byte[] HexBytes(string text) {
			CheckLength(text.Length);
			if ((text.Length & 1) != 0) throw new FormatException("Hex input must contain pairs of digits.");
			var bytes = new byte[text.Length / 2];
			for (int i = 0; i < bytes.Length; i++) {
				int high = Digit(text[i * 2]), low = Digit(text[i * 2 + 1]);
				if (high < 0 || low < 0) throw new FormatException("Invalid hex digit.");
				bytes[i] = (byte)((high << 4) | low);
			}
			return bytes;
		}
		static int Digit(char ch) => ch >= '0' && ch <= '9' ? ch - '0' : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 : ch >= 'A' && ch <= 'F' ? ch - 'A' + 10 : -1;
		internal static void CheckLength(int length) {
			if (length < 0 || length > StaticLimits.MaximumValueLength) throw new InvalidOperationException("Value length limit reached.");
		}
		internal static readonly Encoding StrictUtf8 = new UTF8Encoding(false, true);

		public static string Decode(string text, string operation, int key = 13) {
			CheckLength(text.Length);
			switch (operation) {
			case "Base64": return StrictUtf8.GetString(Convert.FromBase64String(text));
			case "Hex / UTF-8": return StrictUtf8.GetString(HexBytes(text));
			case "Reverse": return new string(text.Reverse().ToArray());
			case "ROT":
				var rotation = ((key % 26) + 26) % 26;
				return new string(text.Select(ch => ch >= 'a' && ch <= 'z' ? (char)('a' + (ch - 'a' + rotation) % 26) :
					ch >= 'A' && ch <= 'Z' ? (char)('A' + (ch - 'A' + rotation) % 26) : ch).ToArray());
			case "XOR hex / UTF-8":
				if (key < 0 || key > 255) throw new ArgumentOutOfRangeException(nameof(key), "XOR key must be 0–255.");
				var bytes = HexBytes(text);
				for (int i = 0; i < bytes.Length; i++) bytes[i] ^= (byte)key;
				return StrictUtf8.GetString(bytes);
			default: throw new ArgumentException("Unsupported transformation.");
			}
		}

		static readonly Regex secrets = new Regex(@"(https?://(?:discord(?:app)?\.com/api/webhooks/\d+/|hooks\.slack\.com/services/[^\s/]+/[^\s/]+/|api\.telegram\.org/bot))[^\s'""<>/?#]+",
			RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(200));
		public static string Display(string text) {
			try { return secrets.Replace(text, "$1[REDACTED]").Replace("\0", "\\0"); }
			catch (RegexMatchTimeoutException) { return "[REDACTION TIMEOUT]"; }
		}
	}
}
