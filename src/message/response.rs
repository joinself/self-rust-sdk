use serde::{Deserialize, Serialize};

use crate::error::SelfError;

use super::ResponseStatus;

pub enum Response {
    Connection(ConnectionResponse),
    GroupInvite(GroupInviteResponse),
}

#[derive(Serialize, Deserialize)]
pub struct ConnectionResponse {
    pub ath: Option<Vec<u8>>, // authentication token
    pub ntf: Option<Vec<u8>>, // notification token
    pub sts: ResponseStatus,
}

impl ConnectionResponse {
    pub fn encode(&self) -> Result<Vec<u8>, SelfError> {
        let mut data = Vec::new();
        ciborium::ser::into_writer(self, &mut data).map_err(|_| SelfError::TokenEncodingInvalid)?;
        Ok(data)
    }

    pub fn decode(data: &[u8]) -> Result<ConnectionResponse, SelfError> {
        ciborium::de::from_reader(data).map_err(|_| SelfError::MessageDecodingInvalid)
    }
}

#[derive(Serialize, Deserialize)]
pub struct GroupInviteResponse {
    pub gid: Vec<u8>,         // group identifier
    pub aid: Option<Vec<u8>>, // as identifier, the identifier the invitee would like to use to join the group
    pub ath: Option<Vec<u8>>, // authentication token (optional for when the group inviter is not a connection)
    pub ntf: Option<Vec<u8>>, // notification token (optional, for when the group innviter is not a connection)
    pub sts: ResponseStatus,
}

impl GroupInviteResponse {
    pub fn encode(&self) -> Result<Vec<u8>, SelfError> {
        let mut data = Vec::new();
        ciborium::ser::into_writer(self, &mut data).map_err(|_| SelfError::TokenEncodingInvalid)?;
        Ok(data)
    }

    pub fn decode(data: &[u8]) -> Result<GroupInviteResponse, SelfError> {
        ciborium::de::from_reader(data).map_err(|_| SelfError::MessageDecodingInvalid)
    }
}
