using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
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

namespace dnSpy.StaticAnalysis {
	[ExportExtension]
	sealed class StaticAnalysisExtension : IExtension {
		public IEnumerable<string> MergedResourceDictionaries { get { yield break; } }
		public ExtensionInfo ExtensionInfo => new ExtensionInfo { ShortDescription = "Static constant-string reconstruction and obfuscation profiling" };
		public void OnEvent(ExtensionEvent @event, object? obj) { }
	}
	[Export(typeof(IToolWindowContentProvider))]
	sealed class StaticWindowProvider : IToolWindowContentProvider {
		readonly Lazy<StaticAnalysisService> service;
		StaticWindow? window;
		[ImportingConstructor]
		StaticWindowProvider(Lazy<StaticAnalysisService> service) => this.service = service;
		public IEnumerable<ToolWindowContentInfo> ContentInfos {
			get { yield return new ToolWindowContentInfo(StaticWindow.Id, AppToolWindowLocation.DefaultHorizontal, AppToolWindowConstants.DEFAULT_CONTENT_ORDER_BOTTOM_ANALYZER + 1); }
		}
		public ToolWindowContent? GetOrCreate(Guid guid) => guid == StaticWindow.Id ? window ??= new StaticWindow(service) : null;
	}
	sealed class StaticWindow : ToolWindowContent, IFocusable {
		public static readonly Guid Id = new Guid("3D95FB9E-916B-431C-8FD9-210FD7CC5A74");
		readonly Lazy<StaticAnalysisService> service;
		public StaticWindow(Lazy<StaticAnalysisService> service) => this.service = service;
		public override Guid Guid => Id;
		public override string Title => "Static String Analysis";
		public override object? UIObject => service.Value.Control;
		public override IInputElement? FocusedElement => service.Value.Control;
		public override FrameworkElement? ZoomElement => service.Value.Control;
		public bool CanFocus => true;
		public void Focus() => service.Value.Control.Focus();
	}
	[Export]
	sealed class StaticAnalysisService {
		readonly IDocumentTabService tabs;
		readonly StaticAnalysisControl view = new StaticAnalysisControl();
		CancellationTokenSource? cancellation;
		ModuleDef? selected;
		StaticAnalysisResult? current;
		public FrameworkElement Control => view;
		[ImportingConstructor]
		StaticAnalysisService(IDocumentTabService tabs) {
			this.tabs = tabs;
			view.AnalyzeRequested += AnalyzeSelection;
			view.CancelRequested += () => cancellation?.Cancel();
			view.NavigateRequested += Navigate;
			view.ExportRequested += Export;
			tabs.DocumentModified += (_, e) => { if (Affected(e.Documents)) Invalidate("Module changed. Analyze again."); };
			tabs.DocumentTreeView.DocumentService.CollectionChanged += (_, e) => {
				if (e.Type != NotifyDocumentCollectionType.Add && Affected(e.Documents)) Invalidate("Module removed. Select a .NET module.");
			};
		}
		bool Affected(IDsDocument[] documents) => selected is not null && documents.Any(d => d.ModuleDef == selected || d.AssemblyDef?.Modules.Contains(selected) == true);
		void Invalidate(string message) {
			var previous = cancellation; cancellation = null; previous?.Cancel();
			current = null; view.Clear(message); view.SetBusy(false); view.Status = message;
		}
		public void AnalyzeSelection() {
			var module = tabs.DocumentTreeView.TreeView.SelectedItems.OfType<DocumentTreeNodeData>().Select(n => n.GetModule()).FirstOrDefault(m => m is not null);
			if (module is null) { view.Status = "Select a .NET module or member in the document tree."; return; }
			Invalidate("Analyzing " + module.Name); selected = module;
			var source = cancellation = new CancellationTokenSource();
			view.SetBusy(true); _ = Run(module, source);
		}
		async Task Run(ModuleDef module, CancellationTokenSource source) {
			try {
				var progress = new Progress<string>(name => { if (source == cancellation) view.Status = name + "..."; });
				var result = await Task.Run(() => new StaticAnalysisCoordinator().Analyze(module, source.Token, name => ((IProgress<string>)progress).Report(name)), source.Token);
				if (source != cancellation) return;
				current = result; view.ShowResult(result);
			} catch (OperationCanceledException) { if (source == cancellation) view.Status = "Static analysis canceled or timed out. No current report is available."; }
			catch (Exception ex) { Debug.WriteLine("Static String Analysis: " + ex); if (source == cancellation) view.Status = "Static analysis failed. See debug output."; }
			finally { if (source == cancellation) { cancellation = null; view.SetBusy(false); } source.Dispose(); }
		}
		void Navigate(object reference, uint? offset) {
			tabs.FollowReference(reference, false, true, args => {
				if (args.HasMovedCaret || !args.Success || offset is null || reference is not MethodDef method) return;
				if (args.Tab.TryGetDocumentViewer() is { } viewer && viewer.GetMethodDebugService().FindByCodeOffset(method, offset.Value) is { } statement)
					viewer.MoveCaretToPosition(statement.Statement.TextSpan.Start);
			});
		}
		void Export() {
			if (current is null) return;
			var dialog = new SaveFileDialog { Filter = "Plain text|*.txt", FileName = "static-string-analysis.txt" };
			if (dialog.ShowDialog() != true) return;
			try { File.WriteAllText(dialog.FileName, StaticReportWriter.Write(current)); view.Status = "Report saved."; }
			catch (Exception ex) { Debug.WriteLine(ex); view.Status = "Report could not be saved."; }
		}
	}
	public static class StaticReportWriter {
		public static string Write(StaticAnalysisResult result) {
			var text = new StringBuilder();
			text.AppendLine("STATIC STRING ANALYSIS / OBFUSCATION PROFILE"); text.AppendLine(result.ModuleName);
			text.AppendLine("Static analysis only. The sample was not executed and no discovered network endpoint was contacted. Static analysis establishes code and indicators present in the file, but cannot prove that every runtime capability successfully executes on a particular system.");
			text.AppendLine("Obfuscation indicators: " + result.ProfileLevel + " (not a malware score)");
			foreach (var indicator in result.Indicators) { text.AppendLine(indicator.RuleId + " | " + indicator.Level + " | " + indicator.Title); text.AppendLine(indicator.Explanation); foreach (var evidence in indicator.Evidence) text.AppendLine("  " + evidence.Description); }
			foreach (var item in result.Strings) { text.AppendLine("\r\nOriginal: " + item.Original); text.AppendLine("Decoded: " + item.Decoded); text.AppendLine("Transformation: " + item.Transformation); text.AppendLine("Source: " + item.Source); text.AppendLine(item.Interpretation); }
			foreach (var item in result.Crypto) text.AppendLine("AES observation: " + item.Algorithm + " | " + item.Property + " | " + item.Value + " | " + item.Source);
			text.AppendLine("\r\nMethods inspected: " + result.MethodsInspected + "; methods with unresolved operations/limits: " + result.MethodsWithUnresolvedOperations);
			foreach (var limit in result.Limitations) text.AppendLine(limit);
			return text.ToString();
		}
	}
	[ExportMenuItem(OwnerGuid = MenuConstants.APP_MENU_SECURITY_GUID, Header = "Static String Analysis", Group = MenuConstants.GROUP_APP_MENU_SECURITY_ANALYSIS, Order = 10)]
	sealed class StaticAnalysisCommand : MenuItemBase {
		readonly IDsToolWindowService windows;
		readonly StaticAnalysisService service;
		[ImportingConstructor]
		StaticAnalysisCommand(IDsToolWindowService windows, StaticAnalysisService service) { this.windows = windows; this.service = service; }
		public override void Execute(IMenuItemContext context) { windows.Show(StaticWindow.Id); service.AnalyzeSelection(); }
	}
}
