use xsec_binary_analysis_core::{analyze, AnalysisMode, ManagedSample};

#[test]
fn analyzes_a_real_native_executable_with_the_pinned_recurse_engine() {
    let executable = std::env::current_exe().expect("current test executable");
    let sample = ManagedSample {
        sample_id: "real-test-executable".into(),
        sample_sha256: "a".repeat(64),
        format: "native".into(),
        architecture: None,
        slice: None,
        managed_path: executable,
    };
    let result = analyze(&sample, AnalysisMode::Fast, None).expect("fast analysis succeeds");
    assert_eq!(result.revision.mode, AnalysisMode::Fast);
    assert!(result.summary.get("path").is_none());
    assert!(result
        .functions
        .iter()
        .all(|item| item["address"]["value"].as_str().is_some()));
}
