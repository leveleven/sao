//! Pre-exec policy: deny list from config.

use crate::config::PolicyConfig;
use crate::CoreError;

pub fn check_shell(policy: &PolicyConfig, shell: &str) -> Result<(), CoreError> {
    for pat in &policy.deny_substrings {
        if shell.contains(pat) {
            return Err(CoreError::PolicyDenied(format!(
                "matched deny pattern: {pat:?}"
            )));
        }
    }
    Ok(())
}
