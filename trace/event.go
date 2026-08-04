package apxtrace

// Source identifies where an event originated.
const (
	SourceCluster = "cluster"
	SourceApp     = "app"
)

// Event type constants. Keep in sync with
// lib/approximated/debug_requests/events.ex on the app side.
const (
	EventClusterReceived        = "cluster_received"
	EventClusterResponseStarted = "cluster_response_started"
	EventClusterResponse        = "cluster_response"
	EventRouteMatched           = "route_matched"
	EventEdgeSequenceEntered    = "edge_sequence_entered"
	EventRequestMutation        = "request_mutation"
	EventResponseMutation       = "response_mutation"
	EventUpstreamRequest        = "upstream_request"
	EventUpstreamResponse       = "upstream_response"
	EventUpstreamError          = "upstream_error"
	EventEventsDropped          = "events_dropped"
)

// Event is the wire format POSTed to the app's event sink endpoint.
type Event struct {
	Type    string         `json:"type"`
	TsNs    int64          `json:"ts_ns"`
	Source  string         `json:"source"`
	Payload map[string]any `json:"payload"`
}
