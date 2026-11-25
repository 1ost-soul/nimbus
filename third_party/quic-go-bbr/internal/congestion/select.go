package congestion

import (
	"os"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlogwriter"
)

// NewSendAlgorithm selects the congestion controller for a new connection.
// BBR is the default in this fork; set QUIC_CONGESTION_CONTROL=reno to restore
// the upstream RFC 9002 sender.
func NewSendAlgorithm(rttStats *utils.RTTStats, initialMaxDatagramSize protocol.ByteCount, qlogger qlogwriter.Recorder) SendAlgorithm {
	if os.Getenv("QUIC_CONGESTION_CONTROL") == "reno" {
		return NewRenoSender(rttStats, initialMaxDatagramSize, qlogger)
	}
	return NewBbrSender(rttStats, initialMaxDatagramSize, qlogger)
}
