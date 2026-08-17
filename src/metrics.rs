use std::{
    sync::atomic::{AtomicU8, AtomicU64, Ordering},
    time::Duration,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceAuthorizationOutcome {
    Created,
    Approved,
    Denied,
    Pending,
    SlowDown,
    TokenIssued,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MfaOutcome {
    Challenged,
    Success,
    Failure,
    Rejected,
}

#[derive(Default)]
pub struct Metrics {
    http_requests: AtomicU64,
    http_duration_micros: AtomicU64,
    responses_2xx: AtomicU64,
    responses_3xx: AtomicU64,
    responses_4xx: AtomicU64,
    responses_5xx: AtomicU64,
    authentication_success: AtomicU64,
    authentication_failure: AtomicU64,
    authentication_rejected: AtomicU64,
    rate_limit_rejections: AtomicU64,
    token_exchange_success: AtomicU64,
    token_exchange_failure: AtomicU64,
    pushed_authorization_success: AtomicU64,
    pushed_authorization_failure: AtomicU64,
    device_authorization_created: AtomicU64,
    device_authorization_approved: AtomicU64,
    device_authorization_denied: AtomicU64,
    device_authorization_pending: AtomicU64,
    device_authorization_slow_down: AtomicU64,
    device_authorization_token_issued: AtomicU64,
    device_authorization_rejected: AtomicU64,
    mfa_challenged: AtomicU64,
    mfa_success: AtomicU64,
    mfa_failure: AtomicU64,
    mfa_rejected: AtomicU64,
    configuration_activated: AtomicU64,
    configuration_unchanged: AtomicU64,
    configuration_failed: AtomicU64,
    readiness_state: AtomicU8,
}

impl Metrics {
    pub fn record_http_response(&self, status: u16, duration: Duration) {
        self.http_requests.fetch_add(1, Ordering::Relaxed);
        self.http_duration_micros.fetch_add(
            duration.as_micros().min(u128::from(u64::MAX)) as u64,
            Ordering::Relaxed,
        );
        match status / 100 {
            2 => &self.responses_2xx,
            3 => &self.responses_3xx,
            4 => &self.responses_4xx,
            _ => &self.responses_5xx,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    pub fn authentication(&self, success: bool) {
        if success {
            &self.authentication_success
        } else {
            &self.authentication_failure
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    pub fn rate_limit_rejection(&self) {
        self.request_rate_limit_rejection();
        self.authentication_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn request_rate_limit_rejection(&self) {
        self.rate_limit_rejections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn token_exchange(&self, success: bool) {
        if success {
            &self.token_exchange_success
        } else {
            &self.token_exchange_failure
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    pub fn pushed_authorization(&self, success: bool) {
        if success {
            &self.pushed_authorization_success
        } else {
            &self.pushed_authorization_failure
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    pub fn device_authorization(&self, outcome: DeviceAuthorizationOutcome) {
        match outcome {
            DeviceAuthorizationOutcome::Created => &self.device_authorization_created,
            DeviceAuthorizationOutcome::Approved => &self.device_authorization_approved,
            DeviceAuthorizationOutcome::Denied => &self.device_authorization_denied,
            DeviceAuthorizationOutcome::Pending => &self.device_authorization_pending,
            DeviceAuthorizationOutcome::SlowDown => &self.device_authorization_slow_down,
            DeviceAuthorizationOutcome::TokenIssued => &self.device_authorization_token_issued,
            DeviceAuthorizationOutcome::Rejected => &self.device_authorization_rejected,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    pub fn mfa(&self, outcome: MfaOutcome) {
        match outcome {
            MfaOutcome::Challenged => &self.mfa_challenged,
            MfaOutcome::Success => &self.mfa_success,
            MfaOutcome::Failure => &self.mfa_failure,
            MfaOutcome::Rejected => &self.mfa_rejected,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    pub fn configuration_activated(&self) {
        self.configuration_activated.fetch_add(1, Ordering::Relaxed);
    }

    pub fn configuration_failed(&self) {
        self.configuration_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn configuration_unchanged(&self) {
        self.configuration_unchanged.fetch_add(1, Ordering::Relaxed);
    }

    pub fn readiness_changed(&self, ready: bool) -> bool {
        let state = if ready { 1 } else { 2 };
        self.readiness_state.swap(state, Ordering::Relaxed) != state
    }

    pub fn render(&self, revision: &str, ready: bool) -> String {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let request_count = load(&self.http_requests);
        let duration_seconds = load(&self.http_duration_micros) as f64 / 1_000_000.0;
        format!(
            concat!(
                "# HELP robine_id_ready Whether configuration and PostgreSQL are ready.\n",
                "# TYPE robine_id_ready gauge\n",
                "robine_id_ready {}\n",
                "# HELP robine_id_configuration_info Active semantic configuration revision.\n",
                "# TYPE robine_id_configuration_info gauge\n",
                "robine_id_configuration_info{{revision=\"{}\"}} 1\n",
                "# HELP robine_id_http_requests_total HTTP responses served.\n",
                "# TYPE robine_id_http_requests_total counter\n",
                "robine_id_http_requests_total {}\n",
                "# HELP robine_id_http_request_duration_seconds Request duration sum and count.\n",
                "# TYPE robine_id_http_request_duration_seconds summary\n",
                "robine_id_http_request_duration_seconds_sum {:.6}\n",
                "robine_id_http_request_duration_seconds_count {}\n",
                "# HELP robine_id_http_responses_total Responses by bounded status class.\n",
                "# TYPE robine_id_http_responses_total counter\n",
                "robine_id_http_responses_total{{class=\"2xx\"}} {}\n",
                "robine_id_http_responses_total{{class=\"3xx\"}} {}\n",
                "robine_id_http_responses_total{{class=\"4xx\"}} {}\n",
                "robine_id_http_responses_total{{class=\"5xx\"}} {}\n",
                "# HELP robine_id_authentication_total Authentication outcomes.\n",
                "# TYPE robine_id_authentication_total counter\n",
                "robine_id_authentication_total{{outcome=\"success\"}} {}\n",
                "robine_id_authentication_total{{outcome=\"failure\"}} {}\n",
                "robine_id_authentication_total{{outcome=\"rejected\"}} {}\n",
                "# HELP robine_id_rate_limit_rejections_total Shared request rate-limit rejections.\n",
                "# TYPE robine_id_rate_limit_rejections_total counter\n",
                "robine_id_rate_limit_rejections_total {}\n",
                "# HELP robine_id_token_exchange_total Token exchange outcomes.\n",
                "# TYPE robine_id_token_exchange_total counter\n",
                "robine_id_token_exchange_total{{outcome=\"success\"}} {}\n",
                "robine_id_token_exchange_total{{outcome=\"failure\"}} {}\n",
                "# HELP robine_id_pushed_authorization_total Pushed authorization request outcomes.\n",
                "# TYPE robine_id_pushed_authorization_total counter\n",
                "robine_id_pushed_authorization_total{{outcome=\"success\"}} {}\n",
                "robine_id_pushed_authorization_total{{outcome=\"failure\"}} {}\n",
                "# HELP robine_id_device_authorization_total Device authorization state-machine outcomes.\n",
                "# TYPE robine_id_device_authorization_total counter\n",
                "robine_id_device_authorization_total{{outcome=\"created\"}} {}\n",
                "robine_id_device_authorization_total{{outcome=\"approved\"}} {}\n",
                "robine_id_device_authorization_total{{outcome=\"denied\"}} {}\n",
                "robine_id_device_authorization_total{{outcome=\"authorization_pending\"}} {}\n",
                "robine_id_device_authorization_total{{outcome=\"slow_down\"}} {}\n",
                "robine_id_device_authorization_total{{outcome=\"token_issued\"}} {}\n",
                "robine_id_device_authorization_total{{outcome=\"rejected\"}} {}\n",
                "# HELP robine_id_mfa_total Multi-factor authentication outcomes.\n",
                "# TYPE robine_id_mfa_total counter\n",
                "robine_id_mfa_total{{outcome=\"challenged\"}} {}\n",
                "robine_id_mfa_total{{outcome=\"success\"}} {}\n",
                "robine_id_mfa_total{{outcome=\"failure\"}} {}\n",
                "robine_id_mfa_total{{outcome=\"rejected\"}} {}\n",
                "# HELP robine_id_configuration_reconciliation_total Configuration outcomes.\n",
                "# TYPE robine_id_configuration_reconciliation_total counter\n",
                "robine_id_configuration_reconciliation_total{{outcome=\"activated\"}} {}\n",
                "robine_id_configuration_reconciliation_total{{outcome=\"unchanged\"}} {}\n",
                "robine_id_configuration_reconciliation_total{{outcome=\"failed\"}} {}\n"
            ),
            u8::from(ready),
            revision,
            request_count,
            duration_seconds,
            request_count,
            load(&self.responses_2xx),
            load(&self.responses_3xx),
            load(&self.responses_4xx),
            load(&self.responses_5xx),
            load(&self.authentication_success),
            load(&self.authentication_failure),
            load(&self.authentication_rejected),
            load(&self.rate_limit_rejections),
            load(&self.token_exchange_success),
            load(&self.token_exchange_failure),
            load(&self.pushed_authorization_success),
            load(&self.pushed_authorization_failure),
            load(&self.device_authorization_created),
            load(&self.device_authorization_approved),
            load(&self.device_authorization_denied),
            load(&self.device_authorization_pending),
            load(&self.device_authorization_slow_down),
            load(&self.device_authorization_token_issued),
            load(&self.device_authorization_rejected),
            load(&self.mfa_challenged),
            load(&self.mfa_success),
            load(&self.mfa_failure),
            load(&self.mfa_rejected),
            load(&self.configuration_activated),
            load(&self.configuration_unchanged),
            load(&self.configuration_failed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exports_only_bounded_metric_labels() {
        let metrics = Metrics::default();
        metrics.record_http_response(200, Duration::from_millis(25));
        metrics.record_http_response(401, Duration::from_millis(5));
        metrics.authentication(false);
        metrics.rate_limit_rejection();
        metrics.token_exchange(false);
        metrics.pushed_authorization(true);
        metrics.device_authorization(DeviceAuthorizationOutcome::Created);
        metrics.device_authorization(DeviceAuthorizationOutcome::SlowDown);
        metrics.mfa(MfaOutcome::Challenged);
        metrics.mfa(MfaOutcome::Rejected);
        let output = metrics.render("abc123", true);

        assert!(output.contains("robine_id_ready 1"));
        assert!(output.contains("revision=\"abc123\""));
        assert!(output.contains("class=\"2xx\"} 1"));
        assert!(output.contains("class=\"4xx\"} 1"));
        assert!(output.contains("outcome=\"failure\"} 1"));
        assert!(output.contains("robine_id_token_exchange_total{outcome=\"failure\"} 1"));
        assert!(output.contains("robine_id_pushed_authorization_total{outcome=\"success\"} 1"));
        assert!(output.contains("robine_id_device_authorization_total{outcome=\"created\"} 1"));
        assert!(output.contains("robine_id_device_authorization_total{outcome=\"slow_down\"} 1"));
        assert!(output.contains("robine_id_mfa_total{outcome=\"challenged\"} 1"));
        assert!(output.contains("robine_id_mfa_total{outcome=\"rejected\"} 1"));
        assert!(!output.contains("subject"));
        assert!(metrics.readiness_changed(true));
        assert!(!metrics.readiness_changed(true));
        assert!(metrics.readiness_changed(false));
    }
}
