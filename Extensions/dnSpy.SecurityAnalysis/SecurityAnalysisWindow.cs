using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using dnlib.DotNet;
using dnSpy.Contracts.Controls;
using dnSpy.Contracts.Decompiler;
using dnSpy.Contracts.Documents;
using dnSpy.Contracts.Documents.Tabs;
using dnSpy.Contracts.Documents.TreeView;
using dnSpy.Contracts.Extension;
using dnSpy.Contracts.Menus;
using dnSpy.Contracts.ToolWindows;
using dnSpy.Contracts.ToolWindows.App;
using Microsoft.Win32;

namespace dnSpy.SecurityAnalysis {
	[ExportExtension]
	sealed class SecurityAnalysisExtension : IExtension {
		public IEnumerable<string> MergedResourceDictionaries { get { yield break; } }
		public ExtensionInfo ExtensionInfo => new ExtensionInfo { ShortDescription = "Static security analysis of loaded .NET modules" };
		public void OnEvent(ExtensionEvent @event, object? obj) { }
	}

	[Export(typeof(IToolWindowContentProvider))]
	sealed class SecurityWindowProvider : IToolWindowContentProvider {
		readonly Lazy<SecurityAnalysisService> service;
		SecurityWindow? content;
		[ImportingConstructor]
		SecurityWindowProvider(Lazy<SecurityAnalysisService> service) => this.service = service;
		public IEnumerable<ToolWindowContentInfo> ContentInfos {
			get { yield return new ToolWindowContentInfo(SecurityWindow.Id, AppToolWindowLocation.DefaultHorizontal, AppToolWindowConstants.DEFAULT_CONTENT_ORDER_BOTTOM_ANALYZER); }
		}
		public ToolWindowContent? GetOrCreate(Guid guid) => guid == SecurityWindow.Id ? content ??= new SecurityWindow(service) : null;
	}

	sealed class SecurityWindow : ToolWindowContent, IFocusable {
		public static readonly Guid Id = new Guid("75B64EA0-394D-4EAD-A235-856D554A3114");
		readonly Lazy<SecurityAnalysisService> service;
		public SecurityWindow(Lazy<SecurityAnalysisService> service) => this.service = service;
		public override Guid Guid => Id;
		public override string Title => "Security Analysis";
		public override object? UIObject => service.Value.Control;
		public override IInputElement? FocusedElement => service.Value.Control;
		public override FrameworkElement? ZoomElement => service.Value.Control;
		public bool CanFocus => true;
		public void Focus() => service.Value.Control.Focus();
	}

	[Export]
	sealed class SecurityAnalysisService {
		readonly IDocumentTabService tabs;
		readonly SecurityDocumentState documentState;
		readonly SecurityCoordinator coordinator = new SecurityCoordinator(new ISecurityAnalyzer[] { new HashAnalyzer(), new PeAnalyzer(), new PyInstallerAnalyzer(), new ResourceAnalyzer(), new ConfigurationAnalyzer(), new HiddenContentAnalyzer(), new ApiAnalyzer(), new StringIocAnalyzer(), new BehaviorAnalyzer(), new BehaviorChainAnalyzer(), new TargetedBehaviorAnalyzer() });
		readonly SecurityAnalysisControl view = new SecurityAnalysisControl();
		CancellationTokenSource? cancellation;
		ModuleDef? selectedModule;
		string selectedPath = string.Empty;
		SecurityResult? current;
		public FrameworkElement Control { get; }

		[ImportingConstructor]
		SecurityAnalysisService(IDocumentTabService tabs, SecurityDocumentState documentState, SecurityAnalysisSettings settings) {
			this.tabs = tabs;
			this.documentState = documentState;
			view.IncludeMlvScan = settings.IncludeMlvScan;
			view.MlvScanOptionChanged += () => {
				settings.SetIncludeMlvScan(view.IncludeMlvScan);
				CancelCurrentAnalysis(); coordinator.Invalidate(); current = null;
				view.ClearResult("Analysis options changed");
			};
			Control = view;
			view.AnalyzeRequested += AnalyzeSelection;
			view.DeepAnalyzeRequested += () => AnalyzeSelection(true);
			view.CancelRequested += () => cancellation?.Cancel();
			view.ExportRequested += ExportReport;
			view.ExportIocsRequested += ExportIocs;
			view.ExtractRequested += async () => await ExtractResourceAsync();
			view.NavigateRequested += FollowEvidence;
			tabs.DocumentModified += (_, e) => {
				coordinator.Invalidate();
				if (!AffectsSelectedModule(e.Documents)) return;
				CancelCurrentAnalysis();
				current = null;
				view.ClearResult("Results out of date");
				view.Status = "Selected module changed. Run analysis again.";
			};
			tabs.DocumentTreeView.DocumentService.CollectionChanged += (_, e) => {
				if (e.Type == NotifyDocumentCollectionType.Add) return;
				coordinator.Invalidate();
				if (!AffectsSelectedModule(e.Documents)) return;
				CancelCurrentAnalysis();
				current = null;
				view.ClearResult("Results out of date");
				view.Status = "Selected module was removed. Select a module and run analysis again.";
			};
		}

		bool AffectsSelectedModule(IDsDocument[] documents) => documents.Any(document =>
			selectedModule is not null && (document.ModuleDef == selectedModule || document.AssemblyDef?.Modules.Contains(selectedModule) == true) ||
			selectedPath.Length > 0 && string.Equals(document.Filename, selectedPath, StringComparison.OrdinalIgnoreCase));

		void CancelCurrentAnalysis() {
			var source = cancellation;
			cancellation = null;
			source?.Cancel();
			view.SetAnalyzing(false);
		}

		void ExportReport() {
			if (current is null || !CheckCoreInput()) return;
			var dialog = new SaveFileDialog { Filter = "Markdown|*.md|JSON|*.json|Plain text|*.txt", FileName = "security-analysis" };
			if (dialog.ShowDialog() != true) return;
			try { File.WriteAllText(dialog.FileName, SecurityReportWriter.Write(current, dialog.FilterIndex)); view.Status = "Report exported: " + dialog.FileName; }
			catch (Exception ex) { Debug.WriteLine("Security report export: " + ex); view.Status = "Report export failed: " + ex.Message; }
		}

		void ExportIocs() {
			if (current is null) return;
			var dialog = new SaveFileDialog { Filter = "Markdown|*.md|JSON|*.json|Plain text|*.txt", FileName = "security-iocs" };
			if (dialog.ShowDialog() != true) return;
			try {
				File.WriteAllText(dialog.FileName, SecurityReportWriter.WriteIocs(current, dialog.FilterIndex));
				view.Status = "IOCs exported: " + dialog.FileName;
			} catch (Exception ex) { Debug.WriteLine("Security IOC export: " + ex); view.Status = "IOC export failed: " + ex.Message; }
		}

		async Task ExtractResourceAsync() {
			if (view.SelectedResource is not SecurityResource resource || resource.Source is null) { view.Status = "Select a resource first."; return; }
			if (resource.Size > AnalysisLimits.MaximumResourceBytes) { view.Status = "Resource exceeds the 64 MiB extraction limit."; return; }
			var safeName = resource.Name.Replace('/', '\\');
			var separator = safeName.LastIndexOf('\\');
			if (separator >= 0) safeName = safeName.Substring(separator + 1);
			foreach (var invalid in Path.GetInvalidFileNameChars()) safeName = safeName.Replace(invalid, '_');
			if (string.IsNullOrWhiteSpace(safeName) || safeName == "." || safeName == "..") safeName = "resource.bin";
			var dialog = new SaveFileDialog { FileName = safeName };
			if (dialog.ShowDialog() != true) return;
			try {
				var destination = dialog.FileName;
				await Task.Run(() => {
					using var input = resource.Source.CreateReader().AsStream();
					if (input.Length > AnalysisLimits.MaximumResourceBytes) throw new InvalidDataException("Resource size limit exceeded.");
					using var output = new FileStream(destination, FileMode.Create, FileAccess.Write);
					var buffer = new byte[65536];
					long total = 0;
					int read;
					while ((read = input.Read(buffer, 0, buffer.Length)) > 0) {
						total += read;
						if (total > AnalysisLimits.MaximumResourceBytes) throw new InvalidDataException("Resource size limit exceeded.");
						output.Write(buffer, 0, read);
					}
				});
				view.Status = "Resource saved: " + dialog.FileName;
			} catch (Exception ex) { Debug.WriteLine("Security resource extract: " + ex); view.Status = "Extraction failed: " + ex.Message; }
		}

		void FollowEvidence(object reference, uint? ilOffset) {
			if (!CheckCoreInput()) return;
			// Resource findings navigate to the metadata consumer, never a host resource
			// deserializer or automatic preview of attacker-controlled serialized objects.
			if (reference is Resource resource) {
				var consumer = current?.HiddenContents.FirstOrDefault(c => c.Reference == resource && c.MethodReference is not null);
				if (consumer?.MethodReference is null) { view.Status = "Resource bytes are available in Hidden content / Resources. No code reference was identified."; return; }
				reference = consumer.MethodReference; ilOffset = consumer.IlOffset;
			}
			tabs.FollowReference(reference, false, true, args => {
				if (args.HasMovedCaret || !args.Success || ilOffset is null || reference is not MethodDef method) return;
				if (args.Tab.TryGetDocumentViewer() is { } viewer && viewer.GetMethodDebugService().FindByCodeOffset(method, ilOffset.Value) is { } statement)
					viewer.MoveCaretToPosition(statement.Statement.TextSpan.Start);
			});
		}

		public void AnalyzeSelection() => AnalyzeSelection(false);
		void AnalyzeSelection(bool deep) {
			var nodes = tabs.DocumentTreeView.TreeView.SelectedItems.OfType<DocumentTreeNodeData>().ToArray();
			var module = nodes.Select(n => n.GetModule()).FirstOrDefault(m => m is not null);
			var path = module?.Location ?? nodes.OfType<DsDocumentNode>().Select(n => n.Document.Filename).FirstOrDefault() ?? string.Empty;
			if (string.IsNullOrEmpty(path) && module is null) { view.Status = "Select a module or PE document in the document tree."; return; }
			CancelCurrentAnalysis();
			current = null;
			view.ClearResult(module?.Name ?? Path.GetFileName(path));
			view.SetAnalyzing(true);
			selectedModule = module;
			selectedPath = path;
			var source = cancellation = new CancellationTokenSource();
			view.Status = "Analyzing " + (module?.Name ?? Path.GetFileName(path)) + "...";
			var options = new SecurityAnalysisOptions {
				IncludeMlvScan = view.IncludeMlvScan, DeepMlvScan = deep,
				MlvScanUnavailableReason = documentState.WasModified(module) ? "The open document was edited. Save and reopen it before using MLVScan." : string.Empty
			};
			_ = RunAnalysis(module, path, source, options);
		}

		bool CheckCoreInput() {
			var hash = (string?)current?.MlvScan.Result?["input"]?["sha256Hash"];
			if (hash is null) return true;
			try { if (!documentState.WasModified(selectedModule) && MlvScanAnalyzer.Hash(MlvScanAnalyzer.ReadInput(selectedPath)) == hash) return true; }
			catch (Exception) { }
			current = null; coordinator.Invalidate(); view.ClearResult("Results out of date");
			view.Status = "The scanned file changed or is unavailable. Reopen it and analyze again.";
			return false;
		}

		async Task RunAnalysis(ModuleDef? module, string path, CancellationTokenSource source, SecurityAnalysisOptions options) {
			try {
				var progress = new Progress<string>(name => { if (source == cancellation) view.Status = "Analyzing: " + name; });
				var result = await Task.Run(() => coordinator.Analyze(path, module, source.Token, name => ((IProgress<string>)progress).Report(name), options), source.Token);
				if (source != cancellation) return;
				current = result;
				view.DisplayResult(result);
				view.Status = (result.AnalysisErrors.Count == 0 ? "Findings: " : "Partial analysis (" + result.AnalysisErrors.Count + " errors/limits). Findings: ") +
					string.Join("  ", Enum.GetValues(typeof(SecuritySeverity)).Cast<SecuritySeverity>().Reverse().Select(s => result.Findings.Count(f => f.Severity == s) + " " + s)) +
					(options.IncludeMlvScan ? " | " + result.MlvScan.Summary : string.Empty);
			} catch (OperationCanceledException) { if (source == cancellation) view.Status = "Analysis canceled or timed out."; }
			catch (Exception ex) { Debug.WriteLine("Security Analysis: " + ex); if (source == cancellation) view.Status = "Analysis failed; see debug output."; }
			finally {
				if (source == cancellation) {
					cancellation = null;
					view.SetAnalyzing(false);
				}
				source.Dispose();
			}
		}
	}

	[ExportMenuItem(OwnerGuid = MenuConstants.APP_MENU_EDIT_GUID, Header = "Security Analysis", Group = MenuConstants.GROUP_APP_MENU_EDIT_FIND, Order = 21)]
	sealed class SecurityAnalysisCommand : MenuItemBase {
		readonly IDsToolWindowService windows;
		readonly SecurityAnalysisService service;
		[ImportingConstructor]
		SecurityAnalysisCommand(IDsToolWindowService windows, SecurityAnalysisService service) { this.windows = windows; this.service = service; }
		public override void Execute(IMenuItemContext context) { windows.Show(SecurityWindow.Id); service.AnalyzeSelection(); }
	}
}
