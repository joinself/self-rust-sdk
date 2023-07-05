use crate::error::SelfError;
use crate::identifier::Identifier;
use crate::storage::Storage;
use crate::token::Token;

use std::sync::MutexGuard;

pub fn token_create_authorization(
    storage: &mut MutexGuard<Storage>,
    to: Option<&Identifier>,
    from: &Identifier,
    expires: Option<i64>,
) -> Result<Token, SelfError> {
    // get keypair for signing...
    let signing_identifier = match from {
        Identifier::Owned(_) => from.clone(),
        Identifier::Referenced(_) => {
            let signing_key = storage.keypair_get(from)?;
            Identifier::Owned(signing_key.as_ref().clone())
        }
    };

    let expires = match expires {
        Some(expires) => expires,
        None => i64::MAX,
    };

    // create a token that never expires
    // TODO make configurable
    let token = Token::Authorization(crate::token::Authorization::new(
        &signing_identifier,
        to,
        expires,
    ));

    // add the token to our own storage so we can track who has been given access
    // this allows us to know which tokens will need to be rotated/revoked, etc
    storage.token_create(&signing_identifier, to, expires, &token)?;

    Ok(token)
}