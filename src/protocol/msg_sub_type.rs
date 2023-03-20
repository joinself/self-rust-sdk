// automatically generated by the FlatBuffers compiler, do not modify
extern crate flatbuffers;
use self::flatbuffers::{EndianScalar, Follow};
use super::*;
use std::cmp::Ordering;
use std::mem;
#[deprecated(
    since = "2.0.0",
    note = "Use associated constants instead. This will no longer be generated in 2021."
)]
pub const ENUM_MIN_MSG_SUB_TYPE: u16 = 0;
#[deprecated(
    since = "2.0.0",
    note = "Use associated constants instead. This will no longer be generated in 2021."
)]
pub const ENUM_MAX_MSG_SUB_TYPE: u16 = 18;
#[deprecated(
    since = "2.0.0",
    note = "Use associated constants instead. This will no longer be generated in 2021."
)]
#[allow(non_camel_case_types)]
pub const ENUM_VALUES_MSG_SUB_TYPE: [MsgSubType; 19] = [
    MsgSubType::Unknown,
    MsgSubType::AuthenticationReq,
    MsgSubType::AuthenticationResp,
    MsgSubType::AuthenticationQRResp,
    MsgSubType::AuthenticationDeepLinkResp,
    MsgSubType::FactReq,
    MsgSubType::FactResp,
    MsgSubType::FactQRResp,
    MsgSubType::FactDeepLinkResp,
    MsgSubType::EmailSecurityCodeReq,
    MsgSubType::EmailSecurityCodeResp,
    MsgSubType::PhoneSecurityCodeReq,
    MsgSubType::PhoneSecurityCodeResp,
    MsgSubType::PhoneVerificationReq,
    MsgSubType::PhoneVerificationResp,
    MsgSubType::EmailVerificationReq,
    MsgSubType::EmailVerificationResp,
    MsgSubType::DocumentVerificationReq,
    MsgSubType::DocumentVerificationResp,
];

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct MsgSubType(pub u16);
#[allow(non_upper_case_globals)]
impl MsgSubType {
    pub const Unknown: Self = Self(0);
    pub const AuthenticationReq: Self = Self(1);
    pub const AuthenticationResp: Self = Self(2);
    pub const AuthenticationQRResp: Self = Self(3);
    pub const AuthenticationDeepLinkResp: Self = Self(4);
    pub const FactReq: Self = Self(5);
    pub const FactResp: Self = Self(6);
    pub const FactQRResp: Self = Self(7);
    pub const FactDeepLinkResp: Self = Self(8);
    pub const EmailSecurityCodeReq: Self = Self(9);
    pub const EmailSecurityCodeResp: Self = Self(10);
    pub const PhoneSecurityCodeReq: Self = Self(11);
    pub const PhoneSecurityCodeResp: Self = Self(12);
    pub const PhoneVerificationReq: Self = Self(13);
    pub const PhoneVerificationResp: Self = Self(14);
    pub const EmailVerificationReq: Self = Self(15);
    pub const EmailVerificationResp: Self = Self(16);
    pub const DocumentVerificationReq: Self = Self(17);
    pub const DocumentVerificationResp: Self = Self(18);

    pub const ENUM_MIN: u16 = 0;
    pub const ENUM_MAX: u16 = 18;
    pub const ENUM_VALUES: &'static [Self] = &[
        Self::Unknown,
        Self::AuthenticationReq,
        Self::AuthenticationResp,
        Self::AuthenticationQRResp,
        Self::AuthenticationDeepLinkResp,
        Self::FactReq,
        Self::FactResp,
        Self::FactQRResp,
        Self::FactDeepLinkResp,
        Self::EmailSecurityCodeReq,
        Self::EmailSecurityCodeResp,
        Self::PhoneSecurityCodeReq,
        Self::PhoneSecurityCodeResp,
        Self::PhoneVerificationReq,
        Self::PhoneVerificationResp,
        Self::EmailVerificationReq,
        Self::EmailVerificationResp,
        Self::DocumentVerificationReq,
        Self::DocumentVerificationResp,
    ];
    /// Returns the variant's name or "" if unknown.
    pub fn variant_name(self) -> Option<&'static str> {
        match self {
            Self::Unknown => Some("Unknown"),
            Self::AuthenticationReq => Some("AuthenticationReq"),
            Self::AuthenticationResp => Some("AuthenticationResp"),
            Self::AuthenticationQRResp => Some("AuthenticationQRResp"),
            Self::AuthenticationDeepLinkResp => Some("AuthenticationDeepLinkResp"),
            Self::FactReq => Some("FactReq"),
            Self::FactResp => Some("FactResp"),
            Self::FactQRResp => Some("FactQRResp"),
            Self::FactDeepLinkResp => Some("FactDeepLinkResp"),
            Self::EmailSecurityCodeReq => Some("EmailSecurityCodeReq"),
            Self::EmailSecurityCodeResp => Some("EmailSecurityCodeResp"),
            Self::PhoneSecurityCodeReq => Some("PhoneSecurityCodeReq"),
            Self::PhoneSecurityCodeResp => Some("PhoneSecurityCodeResp"),
            Self::PhoneVerificationReq => Some("PhoneVerificationReq"),
            Self::PhoneVerificationResp => Some("PhoneVerificationResp"),
            Self::EmailVerificationReq => Some("EmailVerificationReq"),
            Self::EmailVerificationResp => Some("EmailVerificationResp"),
            Self::DocumentVerificationReq => Some("DocumentVerificationReq"),
            Self::DocumentVerificationResp => Some("DocumentVerificationResp"),
            _ => None,
        }
    }
}
impl std::fmt::Debug for MsgSubType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Some(name) = self.variant_name() {
            f.write_str(name)
        } else {
            f.write_fmt(format_args!("<UNKNOWN {:?}>", self.0))
        }
    }
}
impl<'a> flatbuffers::Follow<'a> for MsgSubType {
    type Inner = Self;
    #[inline]
    fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
        let b = unsafe { flatbuffers::read_scalar_at::<u16>(buf, loc) };
        Self(b)
    }
}

impl flatbuffers::Push for MsgSubType {
    type Output = MsgSubType;
    #[inline]
    fn push(&self, dst: &mut [u8], _rest: &[u8]) {
        unsafe {
            flatbuffers::emplace_scalar::<u16>(dst, self.0);
        }
    }
}

impl flatbuffers::EndianScalar for MsgSubType {
    #[inline]
    fn to_little_endian(self) -> Self {
        let b = u16::to_le(self.0);
        Self(b)
    }
    #[inline]
    #[allow(clippy::wrong_self_convention)]
    fn from_little_endian(self) -> Self {
        let b = u16::from_le(self.0);
        Self(b)
    }
}

impl<'a> flatbuffers::Verifiable for MsgSubType {
    #[inline]
    fn run_verifier(
        v: &mut flatbuffers::Verifier,
        pos: usize,
    ) -> Result<(), flatbuffers::InvalidFlatbuffer> {
        use self::flatbuffers::Verifiable;
        u16::run_verifier(v, pos)
    }
}

impl flatbuffers::SimpleToVerifyInSlice for MsgSubType {}