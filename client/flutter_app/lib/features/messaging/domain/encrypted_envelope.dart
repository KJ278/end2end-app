/// Transport-safe encrypted message envelope.
///
/// The server may route these fields but cannot decrypt [ciphertext]. Message
/// bodies, attachments, reactions, replies, edits, deletes, receipts, and typing
/// state are encoded inside encrypted payloads unless explicitly required for
/// delivery semantics.
final class EncryptedEnvelope {
  const EncryptedEnvelope({
    required this.envelopeId,
    required this.conversationId,
    required this.senderDeviceId,
    required this.recipientDeviceIds,
    required this.ratchetHeader,
    required this.associatedData,
    required this.nonce,
    required this.ciphertext,
    required this.authenticationTag,
  });

  final String envelopeId;
  final String conversationId;
  final String senderDeviceId;
  final List<String> recipientDeviceIds;
  final RatchetHeader ratchetHeader;
  final List<int> associatedData;
  final List<int> nonce;
  final List<int> ciphertext;
  final List<int> authenticationTag;
}

final class RatchetHeader {
  const RatchetHeader({
    required this.senderRatchetPublicKeyX25519,
    required this.previousChainLength,
    required this.messageNumber,
  });

  final List<int> senderRatchetPublicKeyX25519;
  final int previousChainLength;
  final int messageNumber;
}
