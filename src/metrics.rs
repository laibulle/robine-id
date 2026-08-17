use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

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
    configuration_activated: AtomicU64,
    configuration_unchanged: AtomicU64,
    configuration_failed: AtomicU64,
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
        self.rate_limit_rejections.fetch_add(1, Ordering::Relaxed);
        self.authentication_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn token_exchange_success(&self) {
        self.token_exchange_success.fetch_add(1, Ordering::Relaxed);
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
                "# HELP robine_id_rate_limit_rejections_total Authentication rate-limit rejections.\n",
                "# TYPE robine_id_rate_limit_rejections_total counter\n",
                "robine_id_rate_limit_rejections_total {}\n",
                "# HELP robine_id_token_exchange_total Successful token exchanges.\n",
                "# TYPE robine_id_token_exchange_total counter\n",
                "robine_id_token_exchange_total{{outcome=\"success\"}} {}\n",
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
        let output = metrics.render("abc123", true);

        assert!(output.contains("robine_id_ready 1"));
        assert!(output.contains("revision=\"abc123\""));
        assert!(output.contains("class=\"2xx\"} 1"));
        assert!(output.contains("class=\"4xx\"} 1"));
        assert!(output.contains("outcome=\"failure\"} 1"));
        assert!(!output.contains("subject"));
    }
}
