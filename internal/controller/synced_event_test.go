package controller

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/record"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// Synced 이벤트는 매 폴링이 아니라 상태가 바뀔 때만 남아야 한다.

func drainSyncedEvents(rec *record.FakeRecorder) int {

	n := 0
	for {
		select {
		case e := <-rec.Events:
			if strings.Contains(e, " Synced ") {

				n++
			}
		default:
			return n
		}
	}
}

func TestOctoVault_SyncedEvent_OnlyOnChange(t *testing.T) {

	ctx := context.Background()
	const path = "values/events.yaml"

	fetcher := &staticFetcher{files: map[string][]byte{path: sampleConfigMapYAML}, rev: "rev1"}
	rec, _, ov := newUpdateMetaReconciler(t, path, fetcher)
	recorder := rec.Recorder.(*record.FakeRecorder)
	req := reconcile.Request{NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}}

	_, err := rec.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, 1, drainSyncedEvents(recorder), "first sync emits an event")

	for range 3 {
		_, err = rec.Reconcile(ctx, req)
		require.NoError(t, err)
	}
	assert.Equal(t, 0, drainSyncedEvents(recorder), "unchanged polls must not emit events")

	fetcher.rev = "rev2"
	_, err = rec.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, 1, drainSyncedEvents(recorder), "a new revision emits an event")
}
