# Supplied mod sample validation

Static validation on 2026-09-28 used file bytes, dnlib metadata/IL, resources, and bounded data transformations only. None of the samples were CLR-loaded, invoked, installed as extensions, extracted to executable files, or executed. No discovered endpoint was contacted. SHA-256 checks before/after inspection showed unchanged sample bytes.

| File | Hidden content rows | Focused rule | Startup reference evidence |
| --- | ---: | --- | --- |
| CustomTV_IL2CPP.dll.di | 7 | MOD003 | Yes |
| DynamicOrders.dll.di | 13 | MOD001 | Yes |
| KrobusCourier.dll.di | 4 | MOD001 | Yes |
| LongLastingFertilizer.dll.di | 2 | MOD001 | Yes |
| MelonLoaderMod55.dll.di | 1 | MOD001 | Yes |
| MoreTrees.dll.di | 2 | MOD001 | Yes |
| NoMoreTrash.dll.di | 2 | MOD003 | Yes |
| NoPolice.dll.di | 3 | MOD001 | Yes |
| PlayMakerX.dll.di | 2 | MOD002 | Yes |
| RealRadio.dll.di | 2 | MOD003 | Yes |
| RentalCars.dll.di | 2 | MOD001 | Yes |
| ScheduleIMoreNpcs.dll.di | 5 | MOD004 | Yes |
| Skitching.dll.di | 3 | MOD001 | Yes |
| UnlimitedGraffiti.dll.di | 2 | MOD001 | Yes |
| vortex_backuprtilizer.dll.di | 2 | MOD001 | Yes |

The focused pass found one high-priority chain per file, with no reported coverage errors or parse/read failures on these examples. These rules expose isolated behavior even when the overall identifier/obfuscation profile is low:

- MOD001: download/write/launch references, including download-to-file APIs, PowerShell policy bypass, or download restriction removal when present.
- MOD002: command-string download/launch logic near a process launch reference.
- MOD003: embedded command resource read/copied to disk near a launch reference.
- MOD004: numeric character-code table hiding process/command names, near reflection invocation and startup references.

Three large command resources yielded smaller candidate views through bounded batch normalization. One mod's assembly metadata supplied an endpoint that differed from the visible fallback. Async state-machine and delegate metadata helped connect relevant code to initialization references.

This is a regression/coverage check on supplied examples, **not a representative detection-accuracy benchmark or proof of runtime behavior**. Chains are static reference neighborhoods; argument flow and successful execution remain unestablished. Batch normalization is heuristic, not execution or full cmd emulation. Harmless negative fixtures separately check that disconnected capabilities and a shared logging helper do not create focused chains.
