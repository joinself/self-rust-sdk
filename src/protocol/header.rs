// automatically generated by the FlatBuffers compiler, do not modify
extern crate flatbuffers;
use self::flatbuffers::{EndianScalar, Follow};
use super::*;
use std::cmp::Ordering;
use std::mem;
pub enum HeaderOffset {}
#[derive(Copy, Clone, PartialEq)]

pub struct Header<'a> {
    pub _tab: flatbuffers::Table<'a>,
}

impl<'a> flatbuffers::Follow<'a> for Header<'a> {
    type Inner = Header<'a>;
    #[inline]
    fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
        Self {
            _tab: flatbuffers::Table { buf, loc },
        }
    }
}

impl<'a> Header<'a> {
    pub const VT_ID: flatbuffers::VOffsetT = 4;
    pub const VT_MSGTYPE: flatbuffers::VOffsetT = 6;

    #[inline]
    pub fn init_from_table(table: flatbuffers::Table<'a>) -> Self {
        Header { _tab: table }
    }
    #[allow(unused_mut)]
    pub fn create<'bldr: 'args, 'args: 'mut_bldr, 'mut_bldr>(
        _fbb: &'mut_bldr mut flatbuffers::FlatBufferBuilder<'bldr>,
        args: &'args HeaderArgs<'args>,
    ) -> flatbuffers::WIPOffset<Header<'bldr>> {
        let mut builder = HeaderBuilder::new(_fbb);
        if let Some(x) = args.id {
            builder.add_id(x);
        }
        builder.add_msgtype(args.msgtype);
        builder.finish()
    }

    #[inline]
    pub fn id(&self) -> Option<&'a str> {
        self._tab
            .get::<flatbuffers::ForwardsUOffset<&str>>(Header::VT_ID, None)
    }
    #[inline]
    pub fn msgtype(&self) -> MsgType {
        self._tab
            .get::<MsgType>(Header::VT_MSGTYPE, Some(MsgType::MSG))
            .unwrap()
    }
}

impl flatbuffers::Verifiable for Header<'_> {
    #[inline]
    fn run_verifier(
        v: &mut flatbuffers::Verifier,
        pos: usize,
    ) -> Result<(), flatbuffers::InvalidFlatbuffer> {
        use self::flatbuffers::Verifiable;
        v.visit_table(pos)?
            .visit_field::<flatbuffers::ForwardsUOffset<&str>>("id", Self::VT_ID, false)?
            .visit_field::<MsgType>("msgtype", Self::VT_MSGTYPE, false)?
            .finish();
        Ok(())
    }
}
pub struct HeaderArgs<'a> {
    pub id: Option<flatbuffers::WIPOffset<&'a str>>,
    pub msgtype: MsgType,
}
impl<'a> Default for HeaderArgs<'a> {
    #[inline]
    fn default() -> Self {
        HeaderArgs {
            id: None,
            msgtype: MsgType::MSG,
        }
    }
}

pub struct HeaderBuilder<'a: 'b, 'b> {
    fbb_: &'b mut flatbuffers::FlatBufferBuilder<'a>,
    start_: flatbuffers::WIPOffset<flatbuffers::TableUnfinishedWIPOffset>,
}
impl<'a: 'b, 'b> HeaderBuilder<'a, 'b> {
    #[inline]
    pub fn add_id(&mut self, id: flatbuffers::WIPOffset<&'b str>) {
        self.fbb_
            .push_slot_always::<flatbuffers::WIPOffset<_>>(Header::VT_ID, id);
    }
    #[inline]
    pub fn add_msgtype(&mut self, msgtype: MsgType) {
        self.fbb_
            .push_slot::<MsgType>(Header::VT_MSGTYPE, msgtype, MsgType::MSG);
    }
    #[inline]
    pub fn new(_fbb: &'b mut flatbuffers::FlatBufferBuilder<'a>) -> HeaderBuilder<'a, 'b> {
        let start = _fbb.start_table();
        HeaderBuilder {
            fbb_: _fbb,
            start_: start,
        }
    }
    #[inline]
    pub fn finish(self) -> flatbuffers::WIPOffset<Header<'a>> {
        let o = self.fbb_.end_table(self.start_);
        flatbuffers::WIPOffset::new(o.value())
    }
}

impl std::fmt::Debug for Header<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ds = f.debug_struct("Header");
        ds.field("id", &self.id());
        ds.field("msgtype", &self.msgtype());
        ds.finish()
    }
}
#[inline]
#[deprecated(since = "2.0.0", note = "Deprecated in favor of `root_as...` methods.")]
pub fn get_root_as_header<'a>(buf: &'a [u8]) -> Header<'a> {
    unsafe { flatbuffers::root_unchecked::<Header<'a>>(buf) }
}

#[inline]
#[deprecated(since = "2.0.0", note = "Deprecated in favor of `root_as...` methods.")]
pub fn get_size_prefixed_root_as_header<'a>(buf: &'a [u8]) -> Header<'a> {
    unsafe { flatbuffers::size_prefixed_root_unchecked::<Header<'a>>(buf) }
}

#[inline]
/// Verifies that a buffer of bytes contains a `Header`
/// and returns it.
/// Note that verification is still experimental and may not
/// catch every error, or be maximally performant. For the
/// previous, unchecked, behavior use
/// `root_as_header_unchecked`.
pub fn root_as_header(buf: &[u8]) -> Result<Header, flatbuffers::InvalidFlatbuffer> {
    flatbuffers::root::<Header>(buf)
}
#[inline]
/// Verifies that a buffer of bytes contains a size prefixed
/// `Header` and returns it.
/// Note that verification is still experimental and may not
/// catch every error, or be maximally performant. For the
/// previous, unchecked, behavior use
/// `size_prefixed_root_as_header_unchecked`.
pub fn size_prefixed_root_as_header(buf: &[u8]) -> Result<Header, flatbuffers::InvalidFlatbuffer> {
    flatbuffers::size_prefixed_root::<Header>(buf)
}
#[inline]
/// Verifies, with the given options, that a buffer of bytes
/// contains a `Header` and returns it.
/// Note that verification is still experimental and may not
/// catch every error, or be maximally performant. For the
/// previous, unchecked, behavior use
/// `root_as_header_unchecked`.
pub fn root_as_header_with_opts<'b, 'o>(
    opts: &'o flatbuffers::VerifierOptions,
    buf: &'b [u8],
) -> Result<Header<'b>, flatbuffers::InvalidFlatbuffer> {
    flatbuffers::root_with_opts::<Header<'b>>(opts, buf)
}
#[inline]
/// Verifies, with the given verifier options, that a buffer of
/// bytes contains a size prefixed `Header` and returns
/// it. Note that verification is still experimental and may not
/// catch every error, or be maximally performant. For the
/// previous, unchecked, behavior use
/// `root_as_header_unchecked`.
pub fn size_prefixed_root_as_header_with_opts<'b, 'o>(
    opts: &'o flatbuffers::VerifierOptions,
    buf: &'b [u8],
) -> Result<Header<'b>, flatbuffers::InvalidFlatbuffer> {
    flatbuffers::size_prefixed_root_with_opts::<Header<'b>>(opts, buf)
}
#[inline]
/// Assumes, without verification, that a buffer of bytes contains a Header and returns it.
/// # Safety
/// Callers must trust the given bytes do indeed contain a valid `Header`.
pub unsafe fn root_as_header_unchecked(buf: &[u8]) -> Header {
    flatbuffers::root_unchecked::<Header>(buf)
}
#[inline]
/// Assumes, without verification, that a buffer of bytes contains a size prefixed Header and returns it.
/// # Safety
/// Callers must trust the given bytes do indeed contain a valid size prefixed `Header`.
pub unsafe fn size_prefixed_root_as_header_unchecked(buf: &[u8]) -> Header {
    flatbuffers::size_prefixed_root_unchecked::<Header>(buf)
}
#[inline]
pub fn finish_header_buffer<'a, 'b>(
    fbb: &'b mut flatbuffers::FlatBufferBuilder<'a>,
    root: flatbuffers::WIPOffset<Header<'a>>,
) {
    fbb.finish(root, None);
}

#[inline]
pub fn finish_size_prefixed_header_buffer<'a, 'b>(
    fbb: &'b mut flatbuffers::FlatBufferBuilder<'a>,
    root: flatbuffers::WIPOffset<Header<'a>>,
) {
    fbb.finish_size_prefixed(root, None);
}
