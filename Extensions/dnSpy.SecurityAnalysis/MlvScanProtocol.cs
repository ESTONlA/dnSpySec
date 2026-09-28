namespace dnSpy.SecurityAnalysis {
	// Binary request: protocol version, deep flag, byte count, then exact input bytes.
	// Response: one UTF-8 JSON object. No sample paths or commands cross this boundary.
	public static class MlvScanProtocol {
		public const int Version = 1;
		public const int MaximumInputBytes = 64 * 1024 * 1024;
		public const int MaximumOutputBytes = 32 * 1024 * 1024;
		public const int TimeoutSeconds = 180;
	}
}
