// automatically generated by the FlatBuffers compiler, do not modify
extern crate flatbuffers;
use self::flatbuffers::{EndianScalar, Follow};
use super::*;
use std::cmp::Ordering;
use std::mem;
pub enum MessageOffset {}
#[derive(Copy, Clone, PartialEq)]

pub struct Message<'a> {
    pub _tab: flatbuffers::Table<'a>,
}

impl<'a> flatbuffers::Follow<'a> for Message<'a> {
    type Inner = Message<'a>;
    #[inline]
    fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
        Self {
            _tab: flatbuffers::Table { buf, loc },
        }
    }
}

impl<'a> Message<'a> {
    pub const VT_ID: flatbuffers::VOffsetT = 4;
    pub const VT_MSGTYPE: flatbuffers::VOffsetT = 6;
    pub const VT_SUBTYPE: flatbuffers::VOffsetT = 8;
    pub const VT_SENDER: flatbuffers::VOffsetT = 10;
    pub const VT_RECIPIENT: flatbuffers::VOffsetT = 12;
    pub const VT_METADATA: flatbuffers::VOffsetT = 14;
    pub const VT_CIPHERTEXT: flatbuffers::VOffsetT = 16;
    pub const VT_PRIORITY: flatbuffers::VOffsetT = 20;
    pub const VT_MESSAGE_TYPE: flatbuffers::VOffsetT = 22;
    pub const VT_COLLAPSE_KEY: flatbuffers::VOffsetT = 24;
    pub const VT_NOTIFICATION_PAYLOAD: flatbuffers::VOffsetT = 26;

    #[inline]
    pub fn init_from_table(table: flatbuffers::Table<'a>) -> Self {
        Message { _tab: table }
    }
    #[allow(unused_mut)]
    pub fn create<'bldr: 'args, 'args: 'mut_bldr, 'mut_bldr>(
        _fbb: &'mut_bldr mut flatbuffers::FlatBufferBuilder<'bldr>,
        args: &'args MessageArgs<'args>,
    ) -> flatbuffers::WIPOffset<Message<'bldr>> {
        let mut builder = MessageBuilder::new(_fbb);
        if let Some(x) = args.notification_payload {
            builder.add_notification_payload(x);
        }
        if let Some(x) = args.collapse_key {
            builder.add_collapse_key(x);
        }
        if let Some(x) = args.message_type {
            builder.add_message_type(x);
        }
        builder.add_priority(args.priority);
        if let Some(x) = args.ciphertext {
            builder.add_ciphertext(x);
        }
        if let Some(x) = args.metadata {
            builder.add_metadata(x);
        }
        if let Some(x) = args.recipient {
            builder.add_recipient(x);
        }
        if let Some(x) = args.sender {
            builder.add_sender(x);
        }
        if let Some(x) = args.id {
            builder.add_id(x);
        }
        builder.add_subtype(args.subtype);
        builder.add_msgtype(args.msgtype);
        builder.finish()
    }

    #[inline]
    pub fn id(&self) -> Option<&'a str> {
        self._tab
            .get::<flatbuffers::ForwardsUOffset<&str>>(Message::VT_ID, None)
    }
    #[inline]
    pub fn msgtype(&self) -> MsgType {
        self._tab
            .get::<MsgType>(Message::VT_MSGTYPE, Some(MsgType::MSG))
            .unwrap()
    }
    #[inline]
    pub fn subtype(&self) -> MsgSubType {
        self._tab
            .get::<MsgSubType>(Message::VT_SUBTYPE, Some(MsgSubType::Unknown))
            .unwrap()
    }
    #[inline]
    pub fn sender(&self) -> Option<&'a str> {
        self._tab
            .get::<flatbuffers::ForwardsUOffset<&str>>(Message::VT_SENDER, None)
    }
    #[inline]
    pub fn recipient(&self) -> Option<&'a str> {
        self._tab
            .get::<flatbuffers::ForwardsUOffset<&str>>(Message::VT_RECIPIENT, None)
    }
    #[inline]
    pub fn metadata(&self) -> &'a Metadata {
        self._tab
            .get::<Metadata>(Message::VT_METADATA, None)
            .unwrap()
    }
    #[inline]
    pub fn ciphertext(&self) -> Option<&'a [u8]> {
        self._tab
            .get::<flatbuffers::ForwardsUOffset<flatbuffers::Vector<'a, u8>>>(
                Message::VT_CIPHERTEXT,
                None,
            )
            .map(|v| v.safe_slice())
    }
    #[inline]
    pub fn priority(&self) -> u32 {
        self._tab.get::<u32>(Message::VT_PRIORITY, Some(0)).unwrap()
    }
    #[inline]
    pub fn message_type(&self) -> Option<&'a [u8]> {
        self._tab
            .get::<flatbuffers::ForwardsUOffset<flatbuffers::Vector<'a, u8>>>(
                Message::VT_MESSAGE_TYPE,
                None,
            )
            .map(|v| v.safe_slice())
    }
    #[inline]
    pub fn collapse_key(&self) -> Option<&'a [u8]> {
        self._tab
            .get::<flatbuffers::ForwardsUOffset<flatbuffers::Vector<'a, u8>>>(
                Message::VT_COLLAPSE_KEY,
                None,
            )
            .map(|v| v.safe_slice())
    }
    #[inline]
    pub fn notification_payload(&self) -> Option<&'a [u8]> {
        self._tab
            .get::<flatbuffers::ForwardsUOffset<flatbuffers::Vector<'a, u8>>>(
                Message::VT_NOTIFICATION_PAYLOAD,
                None,
            )
            .map(|v| v.safe_slice())
    }
}

impl flatbuffers::Verifiable for Message<'_> {
    #[inline]
    fn run_verifier(
        v: &mut flatbuffers::Verifier,
        pos: usize,
    ) -> Result<(), flatbuffers::InvalidFlatbuffer> {
        use self::flatbuffers::Verifiable;
        v.visit_table(pos)?
            .visit_field::<flatbuffers::ForwardsUOffset<&str>>("id", Self::VT_ID, false)?
            .visit_field::<MsgType>("msgtype", Self::VT_MSGTYPE, false)?
            .visit_field::<MsgSubType>("subtype", Self::VT_SUBTYPE, false)?
            .visit_field::<flatbuffers::ForwardsUOffset<&str>>("sender", Self::VT_SENDER, false)?
            .visit_field::<flatbuffers::ForwardsUOffset<&str>>(
                "recipient",
                Self::VT_RECIPIENT,
                false,
            )?
            .visit_field::<Metadata>("metadata", Self::VT_METADATA, true)?
            .visit_field::<flatbuffers::ForwardsUOffset<flatbuffers::Vector<'_, u8>>>(
                "ciphertext",
                Self::VT_CIPHERTEXT,
                false,
            )?
            .visit_field::<u32>("priority", Self::VT_PRIORITY, false)?
            .visit_field::<flatbuffers::ForwardsUOffset<flatbuffers::Vector<'_, u8>>>(
                "message_type",
                Self::VT_MESSAGE_TYPE,
                false,
            )?
            .visit_field::<flatbuffers::ForwardsUOffset<flatbuffers::Vector<'_, u8>>>(
                "collapse_key",
                Self::VT_COLLAPSE_KEY,
                false,
            )?
            .visit_field::<flatbuffers::ForwardsUOffset<flatbuffers::Vector<'_, u8>>>(
                "notification_payload",
                Self::VT_NOTIFICATION_PAYLOAD,
                false,
            )?
            .finish();
        Ok(())
    }
}
pub struct MessageArgs<'a> {
    pub id: Option<flatbuffers::WIPOffset<&'a str>>,
    pub msgtype: MsgType,
    pub subtype: MsgSubType,
    pub sender: Option<flatbuffers::WIPOffset<&'a str>>,
    pub recipient: Option<flatbuffers::WIPOffset<&'a str>>,
    pub metadata: Option<&'a Metadata>,
    pub ciphertext: Option<flatbuffers::WIPOffset<flatbuffers::Vector<'a, u8>>>,
    pub priority: u32,
    pub message_type: Option<flatbuffers::WIPOffset<flatbuffers::Vector<'a, u8>>>,
    pub collapse_key: Option<flatbuffers::WIPOffset<flatbuffers::Vector<'a, u8>>>,
    pub notification_payload: Option<flatbuffers::WIPOffset<flatbuffers::Vector<'a, u8>>>,
}
impl<'a> Default for MessageArgs<'a> {
    #[inline]
    fn default() -> Self {
        MessageArgs {
            id: None,
            msgtype: MsgType::MSG,
            subtype: MsgSubType::Unknown,
            sender: None,
            recipient: None,
            metadata: None, // required field
            ciphertext: None,
            priority: 0,
            message_type: None,
            collapse_key: None,
            notification_payload: None,
        }
    }
}

pub struct MessageBuilder<'a: 'b, 'b> {
    fbb_: &'b mut flatbuffers::FlatBufferBuilder<'a>,
    start_: flatbuffers::WIPOffset<flatbuffers::TableUnfinishedWIPOffset>,
}
impl<'a: 'b, 'b> MessageBuilder<'a, 'b> {
    #[inline]
    pub fn add_id(&mut self, id: flatbuffers::WIPOffset<&'b str>) {
        self.fbb_
            .push_slot_always::<flatbuffers::WIPOffset<_>>(Message::VT_ID, id);
    }
    #[inline]
    pub fn add_msgtype(&mut self, msgtype: MsgType) {
        self.fbb_
            .push_slot::<MsgType>(Message::VT_MSGTYPE, msgtype, MsgType::MSG);
    }
    #[inline]
    pub fn add_subtype(&mut self, subtype: MsgSubType) {
        self.fbb_
            .push_slot::<MsgSubType>(Message::VT_SUBTYPE, subtype, MsgSubType::Unknown);
    }
    #[inline]
    pub fn add_sender(&mut self, sender: flatbuffers::WIPOffset<&'b str>) {
        self.fbb_
            .push_slot_always::<flatbuffers::WIPOffset<_>>(Message::VT_SENDER, sender);
    }
    #[inline]
    pub fn add_recipient(&mut self, recipient: flatbuffers::WIPOffset<&'b str>) {
        self.fbb_
            .push_slot_always::<flatbuffers::WIPOffset<_>>(Message::VT_RECIPIENT, recipient);
    }
    #[inline]
    pub fn add_metadata(&mut self, metadata: &Metadata) {
        self.fbb_
            .push_slot_always::<&Metadata>(Message::VT_METADATA, metadata);
    }
    #[inline]
    pub fn add_ciphertext(
        &mut self,
        ciphertext: flatbuffers::WIPOffset<flatbuffers::Vector<'b, u8>>,
    ) {
        self.fbb_
            .push_slot_always::<flatbuffers::WIPOffset<_>>(Message::VT_CIPHERTEXT, ciphertext);
    }
    #[inline]
    pub fn add_priority(&mut self, priority: u32) {
        self.fbb_
            .push_slot::<u32>(Message::VT_PRIORITY, priority, 0);
    }
    #[inline]
    pub fn add_message_type(
        &mut self,
        message_type: flatbuffers::WIPOffset<flatbuffers::Vector<'b, u8>>,
    ) {
        self.fbb_
            .push_slot_always::<flatbuffers::WIPOffset<_>>(Message::VT_MESSAGE_TYPE, message_type);
    }
    #[inline]
    pub fn add_collapse_key(
        &mut self,
        collapse_key: flatbuffers::WIPOffset<flatbuffers::Vector<'b, u8>>,
    ) {
        self.fbb_
            .push_slot_always::<flatbuffers::WIPOffset<_>>(Message::VT_COLLAPSE_KEY, collapse_key);
    }
    #[inline]
    pub fn add_notification_payload(
        &mut self,
        notification_payload: flatbuffers::WIPOffset<flatbuffers::Vector<'b, u8>>,
    ) {
        self.fbb_.push_slot_always::<flatbuffers::WIPOffset<_>>(
            Message::VT_NOTIFICATION_PAYLOAD,
            notification_payload,
        );
    }
    #[inline]
    pub fn new(_fbb: &'b mut flatbuffers::FlatBufferBuilder<'a>) -> MessageBuilder<'a, 'b> {
        let start = _fbb.start_table();
        MessageBuilder {
            fbb_: _fbb,
            start_: start,
        }
    }
    #[inline]
    pub fn finish(self) -> flatbuffers::WIPOffset<Message<'a>> {
        let o = self.fbb_.end_table(self.start_);
        self.fbb_.required(o, Message::VT_METADATA, "metadata");
        flatbuffers::WIPOffset::new(o.value())
    }
}

impl std::fmt::Debug for Message<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ds = f.debug_struct("Message");
        ds.field("id", &self.id());
        ds.field("msgtype", &self.msgtype());
        ds.field("subtype", &self.subtype());
        ds.field("sender", &self.sender());
        ds.field("recipient", &self.recipient());
        ds.field("metadata", &self.metadata());
        ds.field("ciphertext", &self.ciphertext());
        ds.field("priority", &self.priority());
        ds.field("message_type", &self.message_type());
        ds.field("collapse_key", &self.collapse_key());
        ds.field("notification_payload", &self.notification_payload());
        ds.finish()
    }
}
#[inline]
#[deprecated(since = "2.0.0", note = "Deprecated in favor of `root_as...` methods.")]
pub fn get_root_as_message<'a>(buf: &'a [u8]) -> Message<'a> {
    unsafe { flatbuffers::root_unchecked::<Message<'a>>(buf) }
}

#[inline]
#[deprecated(since = "2.0.0", note = "Deprecated in favor of `root_as...` methods.")]
pub fn get_size_prefixed_root_as_message<'a>(buf: &'a [u8]) -> Message<'a> {
    unsafe { flatbuffers::size_prefixed_root_unchecked::<Message<'a>>(buf) }
}

#[inline]
/// Verifies that a buffer of bytes contains a `Message`
/// and returns it.
/// Note that verification is still experimental and may not
/// catch every error, or be maximally performant. For the
/// previous, unchecked, behavior use
/// `root_as_message_unchecked`.
pub fn root_as_message(buf: &[u8]) -> Result<Message, flatbuffers::InvalidFlatbuffer> {
    flatbuffers::root::<Message>(buf)
}
#[inline]
/// Verifies that a buffer of bytes contains a size prefixed
/// `Message` and returns it.
/// Note that verification is still experimental and may not
/// catch every error, or be maximally performant. For the
/// previous, unchecked, behavior use
/// `size_prefixed_root_as_message_unchecked`.
pub fn size_prefixed_root_as_message(
    buf: &[u8],
) -> Result<Message, flatbuffers::InvalidFlatbuffer> {
    flatbuffers::size_prefixed_root::<Message>(buf)
}
#[inline]
/// Verifies, with the given options, that a buffer of bytes
/// contains a `Message` and returns it.
/// Note that verification is still experimental and may not
/// catch every error, or be maximally performant. For the
/// previous, unchecked, behavior use
/// `root_as_message_unchecked`.
pub fn root_as_message_with_opts<'b, 'o>(
    opts: &'o flatbuffers::VerifierOptions,
    buf: &'b [u8],
) -> Result<Message<'b>, flatbuffers::InvalidFlatbuffer> {
    flatbuffers::root_with_opts::<Message<'b>>(opts, buf)
}
#[inline]
/// Verifies, with the given verifier options, that a buffer of
/// bytes contains a size prefixed `Message` and returns
/// it. Note that verification is still experimental and may not
/// catch every error, or be maximally performant. For the
/// previous, unchecked, behavior use
/// `root_as_message_unchecked`.
pub fn size_prefixed_root_as_message_with_opts<'b, 'o>(
    opts: &'o flatbuffers::VerifierOptions,
    buf: &'b [u8],
) -> Result<Message<'b>, flatbuffers::InvalidFlatbuffer> {
    flatbuffers::size_prefixed_root_with_opts::<Message<'b>>(opts, buf)
}
#[inline]
/// Assumes, without verification, that a buffer of bytes contains a Message and returns it.
/// # Safety
/// Callers must trust the given bytes do indeed contain a valid `Message`.
pub unsafe fn root_as_message_unchecked(buf: &[u8]) -> Message {
    flatbuffers::root_unchecked::<Message>(buf)
}
#[inline]
/// Assumes, without verification, that a buffer of bytes contains a size prefixed Message and returns it.
/// # Safety
/// Callers must trust the given bytes do indeed contain a valid size prefixed `Message`.
pub unsafe fn size_prefixed_root_as_message_unchecked(buf: &[u8]) -> Message {
    flatbuffers::size_prefixed_root_unchecked::<Message>(buf)
}
#[inline]
pub fn finish_message_buffer<'a, 'b>(
    fbb: &'b mut flatbuffers::FlatBufferBuilder<'a>,
    root: flatbuffers::WIPOffset<Message<'a>>,
) {
    fbb.finish(root, None);
}

#[inline]
pub fn finish_size_prefixed_message_buffer<'a, 'b>(
    fbb: &'b mut flatbuffers::FlatBufferBuilder<'a>,
    root: flatbuffers::WIPOffset<Message<'a>>,
) {
    fbb.finish_size_prefixed(root, None);
}