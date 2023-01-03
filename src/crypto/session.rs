//use crate::error::SelfError;

use olm_sys::*;

pub struct Session {
    session: *mut OlmSession,
}

impl Session {
    pub unsafe fn ptr(&self) -> *mut OlmSession {
        return self.session;
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            drop(Box::from_raw(self.session));
        }
    }
}
