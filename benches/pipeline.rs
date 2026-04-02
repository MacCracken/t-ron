use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use t_ron::gate::ToolCall;
use t_ron::{DefaultAction, TRon, TRonConfig};

fn permissive_config() -> TRonConfig {
    TRonConfig {
        default_unknown_agent: DefaultAction::Allow,
        default_unknown_tool: DefaultAction::Allow,
        scan_payloads: true,
        analyze_patterns: true,
        ..Default::default()
    }
}

fn make_call(tool: &str, params: serde_json::Value) -> ToolCall {
    ToolCall {
        agent_id: "bench-agent".to_string(),
        tool_name: tool.to_string(),
        params,
        timestamp: chrono::Utc::now(),
    }
}

fn bench_full_pipeline_allow(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let tron = TRon::new(permissive_config());
    let call = make_call("tarang_probe", serde_json::json!({"path": "/test"}));

    c.bench_function("pipeline_allow", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(tron.check(black_box(&call)).await);
        });
    });
}

fn bench_full_pipeline_deny_injection(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let tron = TRon::new(permissive_config());
    let call = make_call(
        "echo",
        serde_json::json!({"q": "1 UNION SELECT * FROM passwords"}),
    );

    c.bench_function("pipeline_deny_injection", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(tron.check(black_box(&call)).await);
        });
    });
}

fn bench_scanner_clean(c: &mut Criterion) {
    let params = serde_json::json!({
        "name": "hello world",
        "count": 42,
        "nested": {"key": "safe value", "list": ["a", "b", "c"]}
    });

    c.bench_function("scanner_clean", |b| {
        b.iter(|| {
            black_box(t_ron::scanner::scan(black_box(&params)));
        });
    });
}

fn bench_scanner_injection(c: &mut Criterion) {
    let params =
        serde_json::json!({"q": "SELECT * FROM users WHERE id=1 UNION SELECT * FROM passwords"});

    c.bench_function("scanner_injection", |b| {
        b.iter(|| {
            black_box(t_ron::scanner::scan(black_box(&params)));
        });
    });
}

fn bench_policy_check(c: &mut Criterion) {
    let tron = TRon::new(TRonConfig::default());
    tron.load_policy(
        r#"
[agent."bench-agent"]
allow = ["tarang_*", "rasa_*"]
deny = ["aegis_*"]
"#,
    )
    .unwrap();

    c.bench_function("policy_check_allow", |b| {
        b.iter(|| {
            // Access policy through the TRon check path indirectly
            let _ = black_box(tron.policy_arc().check("bench-agent", "tarang_probe"));
        });
    });
}

fn bench_rate_limiter(c: &mut Criterion) {
    use t_ron::rate::RateLimiter;

    c.bench_function("rate_limiter_check", |b| {
        let limiter = RateLimiter::new();
        b.iter(|| {
            black_box(limiter.check(black_box("agent"), black_box("tool")));
        });
    });
}

fn bench_pattern_record(c: &mut Criterion) {
    use t_ron::pattern::PatternAnalyzer;

    let analyzer = PatternAnalyzer::new();
    let call = make_call("tarang_probe", serde_json::json!({}));

    c.bench_function("pattern_record", |b| {
        b.iter(|| {
            analyzer.record(black_box(&call));
        });
    });
}

fn bench_audit_log(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let logger = t_ron::audit::AuditLogger::new();
    let call = make_call("tarang_probe", serde_json::json!({}));
    let verdict = t_ron::gate::Verdict::Allow;

    c.bench_function("audit_log", |b| {
        b.to_async(&rt).iter(|| async {
            logger.log(black_box(&call), black_box(&verdict)).await;
        });
    });
}

fn bench_risk_score(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let logger = t_ron::audit::AuditLogger::new();
    let call = make_call("tool", serde_json::json!({}));

    // Pre-populate with 50 events
    rt.block_on(async {
        for _ in 0..50 {
            logger.log(&call, &t_ron::gate::Verdict::Allow).await;
        }
    });

    c.bench_function("risk_score", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(t_ron::score::RiskScorer::score(&logger, "bench-agent").await);
        });
    });
}

fn bench_param_size_large(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let tron = TRon::new(permissive_config());
    // 50KB params — under limit but exercises the counting writer
    let big_val = "x".repeat(50_000);
    let call = make_call("tool", serde_json::json!({"data": big_val}));

    c.bench_function("pipeline_large_params", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(tron.check(black_box(&call)).await);
        });
    });
}

criterion_group!(
    benches,
    bench_full_pipeline_allow,
    bench_full_pipeline_deny_injection,
    bench_scanner_clean,
    bench_scanner_injection,
    bench_policy_check,
    bench_rate_limiter,
    bench_pattern_record,
    bench_audit_log,
    bench_risk_score,
    bench_param_size_large,
);
criterion_main!(benches);
