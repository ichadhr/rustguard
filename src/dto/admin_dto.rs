use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

#[derive(Clone, Serialize, Deserialize, Validate)]
pub struct AddPolicyRequest {
    #[validate(length(
        min = 1,
        max = 100,
        message = "Subject must be between 1 and 100 characters"
    ))]
    pub subject: String,

    #[validate(length(
        min = 1,
        max = 200,
        message = "Object must be between 1 and 200 characters"
    ))]
    pub object: String,

    #[validate(length(
        min = 1,
        max = 50,
        message = "Action must be between 1 and 50 characters"
    ))]
    pub action: String,

    #[validate(custom(function = "validate_policy_effect"))]
    pub effect: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AddPolicyResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Clone, Serialize, Deserialize, Validate)]
pub struct CheckPermissionRequest {
    #[validate(length(
        min = 1,
        max = 100,
        message = "Subject must be between 1 and 100 characters"
    ))]
    pub subject: String,

    #[validate(length(
        min = 1,
        max = 200,
        message = "Object must be between 1 and 200 characters"
    ))]
    pub object: String,

    #[validate(length(
        min = 1,
        max = 50,
        message = "Action must be between 1 and 50 characters"
    ))]
    pub action: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CheckPermissionResponse {
    pub allowed: bool,
    pub subject: String,
    pub object: String,
    pub action: String,
}

fn validate_policy_effect(effect: &str) -> Result<(), ValidationError> {
    match effect {
        "allow" | "deny" => Ok(()),
        "" => Err(ValidationError::new("MISSING")
            .with_message(std::borrow::Cow::Borrowed("Effect is required"))),
        _ => Err(ValidationError::new("INVALID_CHOICE")
            .with_message(std::borrow::Cow::Borrowed("Effect must be either 'allow' or 'deny'"))),
    }
}