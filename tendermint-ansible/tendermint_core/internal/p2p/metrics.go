package p2p

import (
	"fmt"
	"reflect"
	"regexp"
	"sync"

	"github.com/go-kit/kit/metrics"
	"github.com/go-kit/kit/metrics/discard"
	"github.com/go-kit/kit/metrics/prometheus"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
)

const (
	// MetricsSubsystem is a subsystem shared by all metrics exposed by this
	// package.
	MetricsSubsystem = "p2p"
)

var (
	// valueToLabelRegexp is used to find the golang package name and type name
	// so that the name can be turned into a prometheus label where the characters
	// in the label do not include prometheus special characters such as '*' and '.'.
	valueToLabelRegexp = regexp.MustCompile(`\*?(\w+)\.(.*)`)
)

// Metrics contains metrics exposed by this package.
type Metrics struct {
	// Number of peers connected.
	Peers metrics.Gauge
	// Nomber of peers in the peer store database.
	PeersStored metrics.Gauge
	// Number of inactive peers stored.
	PeersInactivated metrics.Gauge

	// Number of bytes received from a given peer.
	PeerReceiveBytesTotal metrics.Counter
	// Number of bytes sent to a given peer.
	PeerSendBytesTotal metrics.Counter
	// Pending bytes to be sent to a given peer.
	PeerPendingSendBytes metrics.Gauge

	// Number of successful connection attempts
	PeersConnectedSuccess metrics.Counter
	// Number of failed connection attempts
	PeersConnectedFailure metrics.Counter

	// Number of peers connected as a result of dialing the
	// peer.
	PeersConnectedOutgoing metrics.Gauge
	// Number of peers connected as a result of the peer dialing
	// this node.
	PeersConnectedIncoming metrics.Gauge

	// RouterPeerQueueRecv defines the time taken to read off of a peer's queue
	// before sending on the connection.
	RouterPeerQueueRecv metrics.Histogram

	// RouterPeerQueueSend defines the time taken to send on a peer's queue which
	// will later be read and sent on the connection (see RouterPeerQueueRecv).
	RouterPeerQueueSend metrics.Histogram

	// RouterChannelQueueSend defines the time taken to send on a p2p channel's
	// queue which will later be consued by the corresponding reactor/service.
	RouterChannelQueueSend metrics.Histogram

	// PeerQueueDroppedMsgs defines the number of messages dropped from a peer's
	// queue for a specific flow (i.e. Channel).
	PeerQueueDroppedMsgs metrics.Counter

	// PeerQueueMsgSize defines the average size of messages sent over a peer's
	// queue for a specific flow (i.e. Channel).
	PeerQueueMsgSize metrics.Gauge

	mtx               *sync.RWMutex
	messageLabelNames map[reflect.Type]string
}

// PrometheusMetrics returns Metrics build using Prometheus client library.
// Optionally, labels can be provided along with their values ("foo",
// "fooValue").
func PrometheusMetrics(namespace string, labelsAndValues ...string) *Metrics {
	labels := []string{}
	for i := 0; i < len(labelsAndValues); i += 2 {
		labels = append(labels, labelsAndValues[i])
	}
	return &Metrics{
		Peers: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "peers",
			Help:      "Number of peers connected.",
		}, labels).With(labelsAndValues...),
		PeersStored: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "peers_stored",
			Help:      "Number of peers in the peer Store",
		}, labels).With(labelsAndValues...),
		PeersInactivated: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "peers_inactivated",
			Help:      "Number of peers inactivated",
		}, labels).With(labelsAndValues...),
		PeersConnectedSuccess: prometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "peers_connected_success",
			Help:      "Number of successful peer connection attempts",
		}, labels).With(labelsAndValues...),
		PeersConnectedFailure: prometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "peers_connected_failure",
			Help:      "Number of unsuccessful peer connection attempts",
		}, labels).With(labelsAndValues...),
		PeersConnectedIncoming: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "peers_connected_incoming",
			Help:      "Number of peers connected by peer dialing this node",
		}, labels).With(labelsAndValues...),
		PeersConnectedOutgoing: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "peers_connected_outgoing",
			Help:      "Number of peers connected by this node dialing the peer",
		}, labels).With(labelsAndValues...),

		PeerReceiveBytesTotal: prometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "peer_receive_bytes_total",
			Help:      "Number of bytes received from a given peer.",
		}, append(labels, "peer_id", "chID", "message_type")).With(labelsAndValues...),

		PeerSendBytesTotal: prometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "peer_send_bytes_total",
			Help:      "Number of bytes sent to a given peer.",
		}, append(labels, "peer_id", "chID", "message_type")).With(labelsAndValues...),

		PeerPendingSendBytes: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "peer_pending_send_bytes",
			Help:      "Number of pending bytes to be sent to a given peer.",
		}, append(labels, "peer_id")).With(labelsAndValues...),

		RouterPeerQueueRecv: prometheus.NewHistogramFrom(stdprometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "router_peer_queue_recv",
			Help:      "The time taken to read off of a peer's queue before sending on the connection.",
		}, labels).With(labelsAndValues...),

		RouterPeerQueueSend: prometheus.NewHistogramFrom(stdprometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "router_peer_queue_send",
			Help:      "The time taken to send on a peer's queue which will later be read and sent on the connection (see RouterPeerQueueRecv).",
		}, labels).With(labelsAndValues...),

		RouterChannelQueueSend: prometheus.NewHistogramFrom(stdprometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "router_channel_queue_send",
			Help:      "The time taken to send on a p2p channel's queue which will later be consued by the corresponding reactor/service.",
		}, labels).With(labelsAndValues...),

		PeerQueueDroppedMsgs: prometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "router_channel_queue_dropped_msgs",
			Help:      "The number of messages dropped from a peer's queue for a specific p2p Channel.",
		}, append(labels, "ch_id")).With(labelsAndValues...),

		PeerQueueMsgSize: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "router_channel_queue_msg_size",
			Help:      "The size of messages sent over a peer's queue for a specific p2p Channel.",
		}, append(labels, "ch_id")).With(labelsAndValues...),

		mtx:               &sync.RWMutex{},
		messageLabelNames: map[reflect.Type]string{},
	}
}

// NopMetrics returns no-op Metrics.
func NopMetrics() *Metrics {
	return &Metrics{
		Peers:                  discard.NewGauge(),
		PeersStored:            discard.NewGauge(),
		PeersConnectedSuccess:  discard.NewCounter(),
		PeersConnectedFailure:  discard.NewCounter(),
		PeersConnectedIncoming: discard.NewGauge(),
		PeersConnectedOutgoing: discard.NewGauge(),
		PeersInactivated:       discard.NewGauge(),
		PeerReceiveBytesTotal:  discard.NewCounter(),
		PeerSendBytesTotal:     discard.NewCounter(),
		PeerPendingSendBytes:   discard.NewGauge(),
		RouterPeerQueueRecv:    discard.NewHistogram(),
		RouterPeerQueueSend:    discard.NewHistogram(),
		RouterChannelQueueSend: discard.NewHistogram(),
		PeerQueueDroppedMsgs:   discard.NewCounter(),
		PeerQueueMsgSize:       discard.NewGauge(),
		mtx:                    &sync.RWMutex{},
		messageLabelNames:      map[reflect.Type]string{},
	}
}

// ValueToMetricLabel is a method that is used to produce a prometheus label value of the golang
// type that is passed in.
// This method uses a map on the Metrics struct so that each label name only needs
// to be produced once to prevent expensive string operations.
func (m *Metrics) ValueToMetricLabel(i interface{}) string {
	t := reflect.TypeOf(i)
	m.mtx.RLock()

	if s, ok := m.messageLabelNames[t]; ok {
		m.mtx.RUnlock()
		return s
	}
	m.mtx.RUnlock()

	s := t.String()
	ss := valueToLabelRegexp.FindStringSubmatch(s)
	l := fmt.Sprintf("%s_%s", ss[1], ss[2])
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.messageLabelNames[t] = l
	return l
}
