---
name: binary-analysis
description: Analyze Host-authorized PE, ELF, Mach-O, Fat Mach-O or WASM samples with structured, evidence-backed XSEC binary tools.
---

# Binary analysis

Only work on samples returned by `binary_sample_import` or `binary_samples_list`.
Never request or construct a local path, radare2 command, shell command, signer secret,
project id, assignment id, session id, role, context handle, PID reuse token or runtime
load base. The XSEC Host supplies that state and rejects caller-owned equivalents.

1. Import the sample and record its `sampleSha256`, format, slice, image and coverage.
   A Fat Mach-O import returns a container plus architecture-specific sample records; choose
   the record with the requested `slice` and pass that record's `sampleId` to analysis.
2. Call `binary_analysis_start` with `mode: "full"` unless the user explicitly chooses
   `"fast"`; poll `binary_job_get` to terminal state before citing results.
3. Use paginated queries. Preserve `nextCursor`, `truncated`, `coverage` and every
   hexadecimal address-space label in the result.
4. Create evidence with `binary_evidence_create` before reporting a conclusion. Evidence
   records sample digest, analysis revision, address range, content digest and tool source.
5. Debug actions, register/memory writes, patch export and signing require the Host approval
   flow. Do not claim approval, bypass it, or retry after denial. For writes include the current
   `expectedStopRevision`; a stale revision is a real failure.
6. Patches are equal-length byte replacements only. For a selected Fat Mach-O slice,
   `fileOffset` is relative to the thin image; Host maps it into the container during export.
   Export never overwrites the source sample.
   Signed PE/Mach-O output must complete Host-managed signing and platform verification.
