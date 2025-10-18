package workerpool

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Goofygiraffe06/zinc/internal/logging"
)

// Task represents a unit of work to be executed by the pool.
// The context is propagated to support cancellation/timeouts per task.
type Task func(ctx context.Context)

// Pool is a bounded worker pool executing submitted tasks.
type Pool struct {
	name     string
	size     int
	queue    chan Task
	wg       sync.WaitGroup
	closed   chan struct{}
	shutdown sync.Once
}

// ErrPoolClosed is returned when submitting to a closed pool.
var ErrPoolClosed = errors.New("worker pool closed")

// New creates a new worker pool with given size and queue capacity.
func New(name string, size, queueCap int) *Pool {
	if size <= 0 {
		size = 1
	}
	if queueCap <= 0 {
		queueCap = 1
	}
	p := &Pool{
		name:   name,
		size:   size,
		queue:  make(chan Task, queueCap),
		closed: make(chan struct{}),
	}
	p.start()
	return p
}

func (p *Pool) start() {
	for i := 0; i < p.size; i++ {
		p.wg.Add(1)
		go func(id int) {
			defer p.wg.Done()
			for {
				select {
				case <-p.closed:
					return
				case task, ok := <-p.queue:
					if !ok {
						return
					}
					// Execute with a guard context to prevent runaway tasks
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					func() {
						defer func() {
							if r := recover(); r != nil {
								logging.ErrorLog("workerpool '%s' worker %d recovered from panic: %v", p.name, id, r)
							}
						}()
						task(ctx)
					}()
					cancel()
				}
			}
		}(i)
	}
}

// Submit enqueues a task for execution.
func (p *Pool) Submit(task Task) error {
	select {
	case <-p.closed:
		return ErrPoolClosed
	default:
	}
	select {
	case p.queue <- task:
		return nil
	default:
		// Queue full; log and drop to protect service
		logging.WarnLog("workerpool '%s' queue full; dropping task", p.name)
		return errors.New("queue full")
	}
}

// Close gracefully shuts down the pool and waits for workers to finish.
func (p *Pool) Close() {
	p.shutdown.Do(func() {
		close(p.closed)
		close(p.queue)
		done := make(chan struct{})
		go func() {
			p.wg.Wait()
			close(done)
		}()
		// Wait with a timeout to avoid blocking indefinitely
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			logging.WarnLog("workerpool '%s' shutdown timed out", p.name)
		}
	})
}
