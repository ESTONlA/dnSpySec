namespace dnSpy.SecurityAnalysis {
	// Binary request: protocol version, deep flag, byte count, then exact input bytes.
	// Response: one UTF-8 JSON object. No sample paths or commands cross this boundary.
	public static class MlvScanProtocol {
		public const int Version = 2;
		public const int StandardMaximumInputBytes = 64 * 1024 * 1024;
		public const int MaximumInputBytes = 128 * 1024 * 1024;
		public static int InputLimit(bool deep) => deep ? MaximumInputBytes : StandardMaximumInputBytes;
		public const int MaximumOutputBytes = 32 * 1024 * 1024;
		public const int TimeoutSeconds = 180;
	}
}
