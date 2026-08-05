package apxtrace

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEventJSON_RoundTrip(t *testing.T) {
	evt := Event{
		Type:   EventClusterReceived,
		TsNs:   1_734_000_000_000_000_000,
		Source: SourceCluster,
		Payload: map[string]any{
			"method": "GET",
			"host":   "example.com",
		},
	}
	b, err := json.Marshal(evt)
	require.NoError(t, err)

	var got Event
	require.NoError(t, json.Unmarshal(b, &got))
	require.Equal(t, evt.Type, got.Type)
	require.Equal(t, evt.TsNs, got.TsNs)
	require.Equal(t, evt.Source, got.Source)
	require.Equal(t, "GET", got.Payload["method"])
}

func TestEventType_AllConstantsNonEmpty(t *testing.T) {
	types := []string{
		EventClusterReceived, EventClusterResponse,
		EventRouteMatched, EventEdgeSequenceEntered, EventRequestMutation,
		EventUpstreamRequest, EventUpstreamResponse, EventUpstreamError,
		EventEventsDropped,
	}
	for _, ty := range types {
		require.NotEmpty(t, ty)
	}
}
