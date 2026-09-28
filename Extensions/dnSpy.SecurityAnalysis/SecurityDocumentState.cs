using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Linq;
using dnlib.DotNet;
using dnSpy.Contracts.Documents.Tabs;
using dnSpy.Contracts.Extension;
using dnSpy.Contracts.Settings;

namespace dnSpy.SecurityAnalysis {
	// Subscribe at startup, including edits made before the Security Analysis panel is opened.
	[ExportAutoLoaded, Export(typeof(SecurityDocumentState))]
	sealed class SecurityDocumentState : IAutoLoaded {
		readonly HashSet<ModuleDef> modified = new HashSet<ModuleDef>();
		[ImportingConstructor]
		SecurityDocumentState(IDocumentTabService tabs) {
			tabs.DocumentModified += (_, e) => {
				foreach (var doc in e.Documents) {
					if (doc.ModuleDef is { } module) modified.Add(module);
					if (doc.AssemblyDef is { } assembly) foreach (var member in assembly.Modules) modified.Add(member);
				}
			};
			tabs.DocumentTreeView.DocumentService.CollectionChanged += (_, _) => {
				// Entries are weakly bounded by documents still open; reopening creates a fresh ModuleDef.
				var open = tabs.DocumentTreeView.GetAllCreatedDocumentNodes().Select(n => n.Document.ModuleDef).Where(m => m is not null).ToArray();
				modified.RemoveWhere(m => !open.Contains(m));
			};
		}
		public bool WasModified(ModuleDef? module) => module is not null && modified.Contains(module);
	}

	[Export]
	sealed class SecurityAnalysisSettings {
		static readonly Guid Id = new Guid("2AAF8343-CE72-4517-8E98-2AAD207C453B");
		readonly ISettingsService service;
		[ImportingConstructor]
		SecurityAnalysisSettings(ISettingsService service) { this.service = service; IncludeMlvScan = service.GetOrCreateSection(Id).Attribute<bool?>(nameof(IncludeMlvScan)) ?? false; }
		public bool IncludeMlvScan { get; private set; }
		public void SetIncludeMlvScan(bool value) { IncludeMlvScan = value; service.RecreateSection(Id).Attribute(nameof(IncludeMlvScan), value); }
	}
}
