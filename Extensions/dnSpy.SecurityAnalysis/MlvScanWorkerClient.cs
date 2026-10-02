using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace dnSpy.SecurityAnalysis {
	public sealed class MlvScanWorkerClient {
		readonly string executable;
		public MlvScanWorkerClient(string? executable = null) => this.executable = executable ?? Path.Combine(
			Path.GetDirectoryName(typeof(MlvScanWorkerClient).Assembly.Location)!, "mlvscan", Environment.Is64BitProcess ? "win-x64" : "win-x86", "dnSpy.MlvScanWorker.exe");

		public async Task<string> ScanAsync(byte[] bytes, bool deep, CancellationToken token) {
			if (bytes.Length == 0 || bytes.Length > MlvScanProtocol.InputLimit(deep)) throw new InvalidDataException("MLVScan input exceeds its limit.");
			if (!File.Exists(executable)) throw new FileNotFoundException("The bundled MLVScan worker is missing.");
			using var job = WorkerJob.Create();
			using var process = new Process { StartInfo = new ProcessStartInfo(executable) {
				UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true,
				RedirectStandardOutput = true, RedirectStandardError = true,
				WorkingDirectory = Path.GetDirectoryName(executable)!
			} };
			token.ThrowIfCancellationRequested();
			if (!process.Start()) throw new IOException("Could not start MLVScan.");
			try {
				job.Assign(process);
				using var stopRegistration = token.Register(() => { try { process.Kill(); } catch (InvalidOperationException) { } catch (Win32Exception) { } });
				var output = ReadBounded(process.StandardOutput.BaseStream, MlvScanProtocol.MaximumOutputBytes, token);
				var error = ReadBounded(process.StandardError.BaseStream, 16384, token);
				var input = WriteInput(process.StandardInput.BaseStream, bytes, deep, token);
				var io = Task.WhenAll(input, output, error);
				while (!process.HasExited) {
					token.ThrowIfCancellationRequested();
					if (input.IsFaulted || output.IsFaulted || error.IsFaulted) {
						process.Kill();
						await io.ConfigureAwait(false);
					}
					await Task.Delay(25, token).ConfigureAwait(false);
				}
				await io.ConfigureAwait(false);
				token.ThrowIfCancellationRequested();
				if (process.ExitCode != 0) throw new InvalidDataException("MLVScan worker failed or exceeded an analysis limit.");
				return Encoding.UTF8.GetString(await output.ConfigureAwait(false));
			}
			finally {
				job.Dispose();
				try { if (!process.HasExited) process.Kill(); process.WaitForExit(5000); }
				catch (InvalidOperationException) { } catch (Win32Exception) { }
			}
		}

		static async Task WriteInput(Stream stream, byte[] bytes, bool deep, CancellationToken token) {
			using (stream) {
				using var header = new MemoryStream();
				using (var writer = new BinaryWriter(header, Encoding.UTF8, true)) { writer.Write(MlvScanProtocol.Version); writer.Write(deep); writer.Write(bytes.Length); }
				var prefix = header.ToArray();
				await stream.WriteAsync(prefix, 0, prefix.Length, token).ConfigureAwait(false);
				await stream.WriteAsync(bytes, 0, bytes.Length, token).ConfigureAwait(false);
			}
		}

		static async Task<byte[]> ReadBounded(Stream stream, int limit, CancellationToken token) {
			using var result = new MemoryStream();
			var buffer = new byte[8192];
			int count;
			while ((count = await stream.ReadAsync(buffer, 0, buffer.Length, token).ConfigureAwait(false)) != 0) {
				if (result.Length + count > limit) throw new InvalidDataException("MLVScan output limit reached.");
				result.Write(buffer, 0, count);
			}
			return result.ToArray();
		}
	}

	// Closing the host or this handle terminates the worker, including during a blocked parser call.
	sealed class WorkerJob : SafeHandleZeroOrMinusOneIsInvalid {
		WorkerJob() : base(true) { }
		public static WorkerJob Create() {
			var job = CreateJobObject(IntPtr.Zero, null);
			if (job.IsInvalid) throw new Win32Exception();
			var limits = new ExtendedLimits();
			limits.Basic.LimitFlags = 0x2000 | 0x100; // KILL_ON_JOB_CLOSE | PROCESS_MEMORY
			limits.ProcessMemoryLimit = new UIntPtr(Environment.Is64BitOperatingSystem ? 1024UL * 1024 * 1024 : 512UL * 1024 * 1024);
			if (!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(typeof(ExtendedLimits)))) { job.Dispose(); throw new Win32Exception(); }
			return job;
		}
		public void Assign(Process process) { if (!AssignProcessToJobObject(this, process.Handle)) throw new Win32Exception(); }
		protected override bool ReleaseHandle() => CloseHandle(handle);
		[StructLayout(LayoutKind.Sequential)] struct BasicLimits {
			public long ProcessUserTime, JobUserTime;
			public uint LimitFlags;
			public UIntPtr MinimumWorkingSet, MaximumWorkingSet;
			public uint ActiveProcessLimit;
			public UIntPtr Affinity;
			public uint PriorityClass, SchedulingClass;
		}
		[StructLayout(LayoutKind.Sequential)] struct IoCounters { public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes; }
		[StructLayout(LayoutKind.Sequential)] struct ExtendedLimits {
			public BasicLimits Basic;
			public IoCounters Io;
			public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemory, PeakJobMemory;
		}
		[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern WorkerJob CreateJobObject(IntPtr attributes, string? name);
		[DllImport("kernel32.dll", SetLastError = true)] static extern bool SetInformationJobObject(WorkerJob job, int informationClass, ref ExtendedLimits information, uint length);
		[DllImport("kernel32.dll", SetLastError = true)] static extern bool AssignProcessToJobObject(WorkerJob job, IntPtr process);
		[DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
	}
}
