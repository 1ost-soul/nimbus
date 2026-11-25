package protocol

// AckedPacketInfo and LostPacketInfo are the per-packet events consumed by the
// ported BBR congestion controller.
type AckedPacketInfo struct {
	PacketNumber PacketNumber
	BytesAcked   ByteCount
}

type LostPacketInfo struct {
	PacketNumber PacketNumber
	BytesLost    ByteCount
}
