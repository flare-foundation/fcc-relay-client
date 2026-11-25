package processors

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/fcc-node/pkg/fdc"
	"github.com/flare-foundation/fcc-relay-client/internal/router/instructions"
	"github.com/flare-foundation/fcc-relay-client/pkg/config"
	"github.com/flare-foundation/fcc-relay-client/pkg/signer"
	"github.com/flare-foundation/go-flare-common/pkg/priority"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/fdc2"
	"github.com/stretchr/testify/require"
)

func TestNewFDC(t *testing.T) {
	t.Parallel()
	key, _ := genKey(t)
	base := NewBase(14, signer.NewLocal(key))

	t.Run("nil cfg yields an empty FDC", func(t *testing.T) {
		f, err := NewFDC(nil, base)
		require.NoError(t, err)
		require.NotNil(t, f)
	})

	t.Run("verifier referencing an undefined queue", func(t *testing.T) {
		cfg := &config.FDC{
			Queues: map[string]priority.Params{},
			Verifiers: map[string]config.Verifier{
				"v": {
					AttType:   "TypeA",
					SourceID:  "SrcA",
					QueueName: "missing",
					Server:    config.Credentials{URL: "http://verifier"},
				},
			},
		}
		_, err := NewFDC(cfg, base)
		require.ErrorContains(t, err, "undefined queue")
	})

	t.Run("duplicate type and source", func(t *testing.T) {
		cfg := &config.FDC{
			Queues: map[string]priority.Params{"q": {MaxAttempts: 1}},
			Verifiers: map[string]config.Verifier{
				"a": {AttType: "TypeA", SourceID: "SrcA", QueueName: "q", Server: config.Credentials{URL: "http://a"}},
				"b": {AttType: "TypeA", SourceID: "SrcA", QueueName: "q", Server: config.Credentials{URL: "http://b"}},
			},
		}
		_, err := NewFDC(cfg, base)
		require.ErrorContains(t, err, "both serve")
		require.ErrorContains(t, err, "TypeA")
	})

	t.Run("verifier with empty type or source", func(t *testing.T) {
		cfg := &config.FDC{
			Queues: map[string]priority.Params{"q": {MaxAttempts: 1}},
			Verifiers: map[string]config.Verifier{
				"v": {AttType: "TypeA", QueueName: "q", Server: config.Credentials{URL: "http://v"}},
			},
		}
		_, err := NewFDC(cfg, base)
		require.ErrorContains(t, err, "empty type or source")
	})

	t.Run("verifier with empty server URL", func(t *testing.T) {
		cfg := &config.FDC{
			Queues: map[string]priority.Params{"q": {MaxAttempts: 1}},
			Verifiers: map[string]config.Verifier{
				"v": {AttType: "TypeA", SourceID: "SrcA", QueueName: "q"},
			},
		}
		_, err := NewFDC(cfg, base)
		require.ErrorContains(t, err, "URL not set")
	})

	t.Run("verifier with unnamed api key", func(t *testing.T) {
		cfg := &config.FDC{
			Queues: map[string]priority.Params{"q": {MaxAttempts: 1}},
			Verifiers: map[string]config.Verifier{
				"v": {AttType: "TypeA", SourceID: "SrcA", QueueName: "q", Server: config.Credentials{URL: "http://v", Key: "secret"}},
			},
		}
		_, err := NewFDC(cfg, base)
		require.ErrorContains(t, err, "unnamed api key")
	})
}

// proveInstruction returns an instruction whose request carries attType and sourceID.
func proveInstruction(t *testing.T, attType, sourceID string) *instructions.Base {
	t.Helper()
	ats, err := config.JoinAttTypeAndSourceID(attType, sourceID)
	require.NoError(t, err)

	req := fdc2.IFdc2HubFdc2AttestationRequest{
		Header: fdc2.IFdc2HubFdc2RequestHeader{
			AttestationType: [32]byte(ats[:32]),
			SourceId:        [32]byte(ats[32:]),
		},
		RequestBody: []byte("request-body"),
	}
	msg, err := fdc.EncodeRequest(req)
	require.NoError(t, err)

	ib := &instructions.Base{Event: &instructions.InstructionSentEvent{InstructionId: [32]byte{0x01}}}
	ib.GeneralData.OriginalMessage = msg

	return ib
}

func TestFDCProcess(t *testing.T) {
	t.Parallel()
	key, _ := genKey(t)
	base := NewBase(14, signer.NewLocal(key))

	newFDC := func(t *testing.T) *FDC {
		t.Helper()
		cfg := &config.FDC{
			Queues: map[string]priority.Params{"q": {MaxAttempts: 1}},
			Verifiers: map[string]config.Verifier{
				"v": {AttType: "TypeA", SourceID: "SrcA", QueueName: "q", Server: config.Credentials{URL: "http://verifier"}},
			},
		}
		f, err := NewFDC(cfg, base)
		require.NoError(t, err)
		return f
	}

	t.Run("queues a matching instruction", func(t *testing.T) {
		t.Parallel()
		f := newFDC(t)
		f.queues["q"].InitiateAndRun(t.Context())

		require.NoError(t, f.Process(t.Context(), proveInstruction(t, "TypeA", "SrcA")))
		require.Eventually(t, func() bool { return f.queues["q"].Length() == 1 }, 2*time.Second, 10*time.Millisecond)
	})

	t.Run("unknown type and source -> declined", func(t *testing.T) {
		t.Parallel()
		key, operator := genKey(t)
		out := make(chan *instructions.Base, 1)
		b := NewBase(14, signer.NewLocal(key))
		b.SetOut(out)
		f, err := NewFDC(nil, b)
		require.NoError(t, err)

		ib := proveInstruction(t, "TypeB", "SrcB")
		ib.Tees = signableBase(common.HexToAddress("0x1111111111111111111111111111111111111111")).Tees
		require.NoError(t, f.Process(t.Context(), ib))
		requireDecline(t, <-out, operator)
	})

	t.Run("cancelled ctx wraps the queue add error", func(t *testing.T) {
		t.Parallel()
		f := newFDC(t) // queue not running: Add blocks, so cancellation wins deterministically
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := f.Process(ctx, proveInstruction(t, "TypeA", "SrcA"))
		require.ErrorContains(t, err, "adding to queue")
	})
}

// TestFDCRetriesThenDeclines runs a real queue against a verifier that
// always answers RETRY: it is asked max_attempts times, then one decline is emitted.
func TestFDCRetriesThenDeclines(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	key, operator := genKey(t)
	out := make(chan *instructions.Base, 2)
	b := NewBase(14, signer.NewLocal(key))
	b.SetOut(out)

	const attempts = 3
	cfg := &config.FDC{
		Queues: map[string]priority.Params{"q": {MaxAttempts: attempts, TimeOff: time.Millisecond}},
		Verifiers: map[string]config.Verifier{
			"v": {AttType: "TypeA", SourceID: "SrcA", QueueName: "q", Server: config.Credentials{URL: "http://verifier"}},
		},
	}
	f, err := NewFDC(cfg, b)
	require.NoError(t, err)

	ats, err := config.JoinAttTypeAndSourceID("TypeA", "SrcA")
	require.NoError(t, err)
	calls := new(atomic.Int32)
	f.handler.verifiers[ats] = countingResponder{calls: calls, res: VerifierResponse{Status: StatusRetry, Message: "not final"}}

	var wg sync.WaitGroup
	f.StartQueues(ctx, &wg)

	ib := proveInstruction(t, "TypeA", "SrcA")
	ib.Tees = signableBase(common.HexToAddress("0x1111111111111111111111111111111111111111")).Tees
	require.NoError(t, f.Process(ctx, ib))

	select {
	case got := <-out:
		requireDecline(t, got, operator)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the decline")
	}
	require.EqualValues(t, attempts, calls.Load())

	// no further attempt or emission follows the final one
	time.Sleep(50 * time.Millisecond)
	require.EqualValues(t, attempts, calls.Load())
	require.Empty(t, out)

	cancel()
	wg.Wait()
}
