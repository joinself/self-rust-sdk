use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::SelfError;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub enum ActionType {
    #[serde(rename = "key.add")]
    KeyAdd,
    #[serde(rename = "key.revoke")]
    KeyRevoke,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub enum KeyRole {
    #[serde(rename = "device.key")]
    Device,
    #[serde(rename = "recovery.key")]
    Recovery,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Action {
    pub kid: String,
    pub did: Option<String>,
    #[serde(rename(serialize = "type", deserialize = "type"))]
    pub role: Option<KeyRole>,
    pub action: ActionType,
    pub effective_from: i64,
    pub key: Option<String>,
}

impl Action {
    pub fn validate(&self) -> Result<(), SelfError> {
        if self.kid.len() < 1 {
            return Err(SelfError::SiggraphActionKeyIDInvalid);
        }

        if self.action == ActionType::KeyAdd {
            if self.key.is_none() {
                return Err(SelfError::SiggraphActionPublicKeyEncodingBad);
            }

            match base64::decode_config(self.key.as_ref().unwrap(), base64::URL_SAFE_NO_PAD) {
                Ok(public_key) => {
                    if public_key.len() != 32 {
                        return Err(SelfError::SiggraphActionPublicKeyLengthBad);
                    }
                }
                Err(_) => return Err(SelfError::SiggraphActionPublicKeyEncodingBad),
            };
        }

        if self.key.is_some() && self.role.is_none() {
            return Err(SelfError::SiggraphActionRoleMissing);
        }

        if self.role.is_some()
            && *self.role.as_ref().unwrap() == KeyRole::Device
            && self.did.is_none()
            && self.action != ActionType::KeyRevoke
        {
            return Err(SelfError::SiggraphActionDeviceIDMissing);
        }

        if self.effective_from < 0  {
            return Err(SelfError::SiggraphActionEffectiveFromInvalid);
        }

        return Ok(());
    }

    pub fn effective_from(&self) -> Option<DateTime<Utc>> {
        if self.effective_from == 0 {
            return None;
        }

        if self.effective_from > i32::MAX as i64 {
            return Some(DateTime::from_utc(
                NaiveDateTime::from_timestamp(self.effective_from / 1000, 0),
                Utc,
            ));
        }

        return Some(DateTime::from_utc(
            NaiveDateTime::from_timestamp(self.effective_from, 0),
            Utc,
        ));
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn serialize_deserialize() {
        let ts = crate::time::time::unix();

        let mut action = Action {
            kid: String::from("kid"),
            did: Some(String::from("did")),
            role: Some(KeyRole::Device),
            action: ActionType::KeyAdd,
            effective_from: ts,
            key: Some(String::from("key")),
        };

        let json = serde_json::to_string(&action).unwrap();

        action = serde_json::from_str(&json).unwrap();

        assert_eq!(action.action, ActionType::KeyAdd);
        assert_eq!(action.effective_from().unwrap().timestamp(), ts);
    }
}
