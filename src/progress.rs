//! Shared progress-bar styles for send, receive, and SFTP transfers.

use indicatif::{ProgressState, ProgressStyle};

/// Build a progress-bar style for a transfer.
///
/// `direction` is displayed literally before the filename, e.g. `"↑"` for
/// send and `"↓"` for receive.  `wide` enables the `{msg}` slot for
/// transient status messages (requires a ≥140-column terminal).
pub fn transfer_style(direction: &str, wide: bool) -> ProgressStyle {
    let template = if wide {
        format!(
            "{{spinner:.green}}  {direction} {{prefix}}  {{percent}}%  \
             {{bar:40.cyan/blue}}  {{compact_bytes}}  {{bytes_per_sec}}  ~{{eta}}  {{msg}}"
        )
    } else {
        format!(
            "{{spinner:.green}}  {direction} {{prefix}}  {{percent}}%  \
             {{bar:40.cyan/blue}}  {{compact_bytes}}  {{bytes_per_sec}}  ~{{eta}}"
        )
    };

    ProgressStyle::with_template(&template)
        .unwrap()
        .with_key(
            "compact_bytes",
            |state: &ProgressState, f: &mut dyn std::fmt::Write| {
                let current = state.pos();
                let total = state.len().unwrap_or(0);
                let (divisor, unit) = if total >= 1 << 30 {
                    (1u64 << 30, "GiB")
                } else if total >= 1 << 20 {
                    (1u64 << 20, "MiB")
                } else if total >= 1 << 10 {
                    (1u64 << 10, "KiB")
                } else {
                    (1, "B")
                };
                let d = divisor as f64;
                let _ = write!(
                    f,
                    "{:.2}/{:.2} {unit}",
                    current as f64 / d,
                    total as f64 / d,
                );
            },
        )
        .progress_chars("━░ ")
}
