use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum ResponseStatus {
    Ignored,
    Accepted,
    Rejected,
}
