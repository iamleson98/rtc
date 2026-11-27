/// AV1 payload format ([RFC 9628]).
pub mod av1;
/// G.711 and G.722 payload formats, which need no fragmentation.
pub mod g7xx;
/// H.264 payload format ([RFC 6184]): STAP-A aggregation and FU-A fragmentation.
pub mod h264;
/// H.265/HEVC payload format ([RFC 7798]).
pub mod h265;
/// H.266/VVC payload format ([RFC 9328]).
pub mod h266;
/// Opus payload format ([RFC 7587]), one packet per frame.
pub mod opus;
/// SMPTE ST 336 (KLV) payload ([RFC 6597]).
pub mod smpte336m;
/// VP8 payload format ([RFC 7741]).
pub mod vp8;
/// VP9 payload format (draft-ietf-payload-vp9).
pub mod vp9;

/// Whether an RTP `payload` of the codec `mime` (such as `video/VP8`, compared case-insensitively)
/// is the first packet of a keyframe.
///
/// `Some(true)` for the start of a keyframe, `Some(false)` for anything else of a known codec (a
/// delta frame, a continuation packet, a truncated payload) and `None` when the codec is not
/// understood, which callers should treat as "cannot tell". Only VP8 is understood so far.
pub fn keyframe_start(mime: &str, payload: &[u8]) -> Option<bool> {
    if mime.eq_ignore_ascii_case("video/vp8") {
        Some(vp8::starts_keyframe(payload))
    } else {
        None
    }
}
