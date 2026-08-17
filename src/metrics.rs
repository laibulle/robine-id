use std::{
    fmt::Write as _,
    sync::atomic::{AtomicU8, AtomicU64, Ordering},
    time::Duration,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenGrant {
    AuthorizationCode,
    RefreshToken,
    ClientCredentials,
    DeviceCode,
    TokenExchange,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethodClass {
    Get,
    Post,
    Head,
    Options,
    Other,
}

impl HttpMethodClass {
    const ALL: [Self; 5] = [
        Self::Get,
        Self::Post,
        Self::Head,
        Self::Options,
        Self::Other,
    ];
    const COUNT: usize = Self::ALL.len();

    pub fn from_method(method: &str) -> Self {
        match method {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "HEAD" => Self::Head,
            "OPTIONS" => Self::Options,
            _ => Self::Other,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Other => "other",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Get => 0,
            Self::Post => 1,
            Self::Head => 2,
            Self::Options => 3,
            Self::Other => 4,
        }
    }
}

impl TokenGrant {
    const ALL: [Self; 6] = [
        Self::AuthorizationCode,
        Self::RefreshToken,
        Self::ClientCredentials,
        Self::DeviceCode,
        Self::TokenExchange,
        Self::Unsupported,
    ];
    const COUNT: usize = Self::ALL.len();

    pub fn from_grant_type(grant_type: &str) -> Self {
        match grant_type {
            "authorization_code" => Self::AuthorizationCode,
            "refresh_token" => Self::RefreshToken,
            "client_credentials" => Self::ClientCredentials,
            "urn:ietf:params:oauth:grant-type:device_code" => Self::DeviceCode,
            "urn:ietf:params:oauth:grant-type:token-exchange" => Self::TokenExchange,
            _ => Self::Unsupported,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::RefreshToken => "refresh_token",
            Self::ClientCredentials => "client_credentials",
            Self::DeviceCode => "device_code",
            Self::TokenExchange => "token_exchange",
            Self::Unsupported => "unsupported",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::AuthorizationCode => 0,
            Self::RefreshToken => 1,
            Self::ClientCredentials => 2,
            Self::DeviceCode => 3,
            Self::TokenExchange => 4,
            Self::Unsupported => 5,
        }
    }
}

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
    http_requests_by_method: [AtomicU64; HttpMethodClass::COUNT],
    http_duration_micros_by_method: [AtomicU64; HttpMethodClass::COUNT],
    responses_2xx: AtomicU64,
    responses_3xx: AtomicU64,
    responses_4xx: AtomicU64,
    responses_5xx: AtomicU64,
    authentication_success: AtomicU64,
    authentication_failure: AtomicU64,
    authentication_rejected: AtomicU64,
    token_issuance_success: [AtomicU64; TokenGrant::COUNT],
    token_issuance_failure: [AtomicU64; TokenGrant::COUNT],
    userinfo_success: AtomicU64,
    userinfo_failure: AtomicU64,
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
    pub fn record_http_response(&self, method: HttpMethodClass, status: u16, duration: Duration) {
        self.http_requests.fetch_add(1, Ordering::Relaxed);
        let duration_micros = duration.as_micros().min(u128::from(u64::MAX)) as u64;
        self.http_duration_micros
            .fetch_add(duration_micros, Ordering::Relaxed);
        self.http_requests_by_method[method.index()].fetch_add(1, Ordering::Relaxed);
        self.http_duration_micros_by_method[method.index()]
            .fetch_add(duration_micros, Ordering::Relaxed);
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

    pub fn token_issuance(&self, grant: TokenGrant, success: bool) {
        let counters = if success {
            &self.token_issuance_success
        } else {
            &self.token_issuance_failure
        };
        counters[grant.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub fn userinfo(&self, success: bool) {
        if success {
            &self.userinfo_success
        } else {
            &self.userinfo_failure
        }
        .fetch_add(1, Ordering::Relaxed);
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
        let mut http_method_metrics = String::from(
            "# HELP robine_id_http_method_requests_total HTTP responses by bounded request method.\n\
# TYPE robine_id_http_method_requests_total counter\n\
# HELP robine_id_http_method_request_duration_seconds Request duration sum and count by bounded method.\n\
# TYPE robine_id_http_method_request_duration_seconds summary\n",
        );
        for method in HttpMethodClass::ALL {
            writeln!(
                http_method_metrics,
                "robine_id_http_method_requests_total{{method=\"{}\"}} {}",
                method.label(),
                load(&self.http_requests_by_method[method.index()])
            )
            .expect("writing metrics to a String cannot fail");
            writeln!(
                http_method_metrics,
                "robine_id_http_method_request_duration_seconds_sum{{method=\"{}\"}} {:.6}",
                method.label(),
                load(&self.http_duration_micros_by_method[method.index()]) as f64 / 1_000_000.0
            )
            .expect("writing metrics to a String cannot fail");
            writeln!(
                http_method_metrics,
                "robine_id_http_method_request_duration_seconds_count{{method=\"{}\"}} {}",
                method.label(),
                load(&self.http_requests_by_method[method.index()])
            )
            .expect("writing metrics to a String cannot fail");
        }
        let mut token_issuance_metrics = String::from(
            "# HELP robine_id_token_issuance_total Token endpoint outcomes by bounded grant type.\n\
# TYPE robine_id_token_issuance_total counter\n",
        );
        for grant in TokenGrant::ALL {
            writeln!(
                token_issuance_metrics,
                "robine_id_token_issuance_total{{grant_type=\"{}\",outcome=\"success\"}} {}",
                grant.label(),
                load(&self.token_issuance_success[grant.index()])
            )
            .expect("writing metrics to a String cannot fail");
            writeln!(
                token_issuance_metrics,
                "robine_id_token_issuance_total{{grant_type=\"{}\",outcome=\"failure\"}} {}",
                grant.label(),
                load(&self.token_issuance_failure[grant.index()])
            )
            .expect("writing metrics to a String cannot fail");
        }
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
                "{}",
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
                "{}",
                "# HELP robine_id_userinfo_total UserInfo response outcomes.\n",
                "# TYPE robine_id_userinfo_total counter\n",
                "robine_id_userinfo_total{{outcome=\"success\"}} {}\n",
                "robine_id_userinfo_total{{outcome=\"failure\"}} {}\n",
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
            http_method_metrics,
            load(&self.responses_2xx),
            load(&self.responses_3xx),
            load(&self.responses_4xx),
            load(&self.responses_5xx),
            load(&self.authentication_success),
            load(&self.authentication_failure),
            load(&self.authentication_rejected),
            token_issuance_metrics,
            load(&self.userinfo_success),
            load(&self.userinfo_failure),
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
        metrics.record_http_response(HttpMethodClass::Get, 200, Duration::from_millis(25));
        metrics.record_http_response(HttpMethodClass::Post, 401, Duration::from_millis(5));
        metrics.record_http_response(
            HttpMethodClass::from_method("ATTACKER-CONTROLLED"),
            405,
            Duration::from_millis(1),
        );
        metrics.authentication(false);
        metrics.token_issuance(TokenGrant::AuthorizationCode, true);
        metrics.token_issuance(TokenGrant::RefreshToken, false);
        metrics.token_issuance(TokenGrant::from_grant_type("attacker-controlled"), false);
        metrics.userinfo(true);
        metrics.userinfo(false);
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
        assert!(output.contains("class=\"4xx\"} 2"));
        assert!(output.contains("robine_id_http_method_requests_total{method=\"GET\"} 1"));
        assert!(output.contains("robine_id_http_method_requests_total{method=\"POST\"} 1"));
        assert!(output.contains("robine_id_http_method_requests_total{method=\"other\"} 1"));
        assert!(output.contains(
            "robine_id_http_method_request_duration_seconds_sum{method=\"GET\"} 0.025000"
        ));
        assert!(!output.contains("ATTACKER-CONTROLLED"));
        assert!(output.contains("outcome=\"failure\"} 1"));
        assert!(output.contains(
            "robine_id_token_issuance_total{grant_type=\"authorization_code\",outcome=\"success\"} 1"
        ));
        assert!(output.contains(
            "robine_id_token_issuance_total{grant_type=\"refresh_token\",outcome=\"failure\"} 1"
        ));
        assert!(output.contains(
            "robine_id_token_issuance_total{grant_type=\"unsupported\",outcome=\"failure\"} 1"
        ));
        assert!(!output.contains("attacker-controlled"));
        assert!(output.contains("robine_id_userinfo_total{outcome=\"success\"} 1"));
        assert!(output.contains("robine_id_userinfo_total{outcome=\"failure\"} 1"));
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
