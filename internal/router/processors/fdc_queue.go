package processors

import (
	"context"
	"fmt"
	"runtime/debug"
	"strconv"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/fcc-relay-client/internal/router/instructions"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/flare-foundation/go-flare-common/pkg/priority"
)

// Weight for ordering of the FDC queues.
//
// An item has higher priority if it has arrived earlier. Arrival is Add time,
// not on-chain order: instructions from one collector batch are stamped in
// scheduler order, microseconds apart.
type Weight struct{ time.Time }

// Self returns the Weight itself.
func (w Weight) Self() Weight {
	return w
}

// Less returns true if t is before w.
func (w Weight) Less(t Weight) bool {
	return t.Before(w.Time)
}

// FDCQueue is a priority queue of FDC instructions ordered by Weight.
type FDCQueue struct {
	*priority.PriorityQueue[*queued, Weight]

	maxAttempts int
}

// queued is an instruction with the number of times it was handled.
// The queue re-pushes the same pointer on retry, so the count survives.
type queued struct {
	ib       *instructions.Base
	attempts int
}

// NewQueue creates a FDC queue.
func NewQueue(params priority.Params, name string) *FDCQueue {
	// Terminal errors must always be drainable; see ProcessOut. params is a value copy.
	params.ErrorChan = true
	queue := priority.NewWithLogger[*queued, Weight](params, name, logger.Logger())

	// the priority queue tries an item max(1, MaxAttempts) times in total
	return &FDCQueue{PriorityQueue: queue, maxAttempts: max(1, params.MaxAttempts)}
}

// Add adds the instruction to the queue with weight w.
func (q *FDCQueue) Add(ctx context.Context, ib *instructions.Base, w Weight) error {
	_, err := q.PriorityQueue.Add(ctx, &queued{ib: ib}, w)
	return err
}

// Handler handles a dequeued instruction.
type Handler interface {
	// Handle handles ib; final is set on the last attempt the queue makes.
	Handle(ctx context.Context, ib *instructions.Base, final bool) error
}

// wrapHandle logs each attempt and wraps handler errors and recovered panics with the
// instruction ID; the queue's worker has no recover, so a panic would kill the relay.
func (q *FDCQueue) wrapHandle(h Handler) func(context.Context, *queued) error {
	return func(ctx context.Context, item *queued) (err error) {
		// id is computed after the defer so even a panic there is recovered
		var id string

		defer func() {
			if rec := recover(); rec != nil {
				err = fmt.Errorf("instruction %s: recovered panic: %v", id, rec)
				logger.Errorf("queue %s: panic handling instruction %s: %v\n%s", q.Name(), id, rec, debug.Stack())
			}
		}()

		id = common.Hash(item.ib.Event.InstructionId).Hex()

		// handlers run one at a time per item: it is re-pushed only after this returns
		item.attempts++

		logger.Debugf("queue %s: handling instruction %s (attempt %d/%d)", q.Name(), id, item.attempts, q.maxAttempts)
		err = h.Handle(ctx, item.ib, item.attempts >= q.maxAttempts)
		if err != nil {
			err = fmt.Errorf("instruction %s: %w", id, err)
			// quote: verifier errors can embed response bodies with control characters.
			logger.Debugf("queue %s: attempt failed: %s", q.Name(), strconv.Quote(err.Error()))
			return err
		}
		return nil
	}
}

// ProcessOut spawns a go routine that dequeues and handles dequeued items, and a
// go routine that logs instructions dropped after their final attempt. Both are
// registered on wg so a caller can wait for them to exit after cancelling ctx.
//
// ProcessOut must be called at most once per queue (StartQueues already does this).
func (q *FDCQueue) ProcessOut(ctx context.Context, wg *sync.WaitGroup, h Handler) {
	handle := q.wrapHandle(h)

	wg.Add(2)

	go func() {
		defer wg.Done()
		for {
			select {
			case err := <-q.Errors:
				logger.Errorf("queue %s: dropping instruction after final attempt: %s", q.Name(), strconv.Quote(err.Error()))
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		for {
			if err := ctx.Err(); err != nil {
				logger.Infof("closing queue %s Run: %v (%d instructions still queued)", q.Name(), err, q.Length())
				return
			}

			q.Dequeue(ctx, handle, nil)
		}
	}()
}
