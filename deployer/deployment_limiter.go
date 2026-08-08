package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrRepositoryTooLarge  = errors.New("repository exceeds deployment size limit")
	ErrDeploymentSaturated = errors.New("deployment capacity is exhausted")
)

// DeploymentLimiter bounds all active deployments and serializes work for one
// deployment target.
type DeploymentLimiter struct {
	slots   chan struct{}
	mu      sync.Mutex
	targets map[string]*deploymentTargetLock
}

type deploymentTargetLock struct {
	locked chan struct{}
	refs   int
}

func NewDeploymentLimiter(maxConcurrent int) *DeploymentLimiter {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	return &DeploymentLimiter{
		slots:   make(chan struct{}, maxConcurrent),
		targets: make(map[string]*deploymentTargetLock),
	}
}

// Acquire takes the target lock before waiting for a global slot, so queued
// work for one target cannot occupy capacity needed by unrelated targets. The
// returned release function must be called exactly once.
func (l *DeploymentLimiter) Acquire(ctx context.Context, target string) (func(), error) {
	if l == nil {
		return nil, fmt.Errorf("deployment limiter is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l.mu.Lock()
	entry := l.targets[target]
	if entry == nil {
		entry = &deploymentTargetLock{locked: make(chan struct{}, 1)}
		l.targets[target] = entry
	}
	entry.refs++
	l.mu.Unlock()

	select {
	case entry.locked <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-entry.locked
			l.releaseReference(target, entry)
			return nil, err
		}
	case <-ctx.Done():
		l.releaseReference(target, entry)
		return nil, ctx.Err()
	}

	select {
	case l.slots <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-l.slots
			<-entry.locked
			l.releaseReference(target, entry)
			return nil, err
		}
	case <-ctx.Done():
		<-entry.locked
		l.releaseReference(target, entry)
		return nil, ctx.Err()
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			<-l.slots
			<-entry.locked
			l.releaseReference(target, entry)
		})
	}, nil
}

func (l *DeploymentLimiter) releaseReference(target string, entry *deploymentTargetLock) {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry.refs--
	if entry.refs == 0 && l.targets[target] == entry {
		delete(l.targets, target)
	}
}

// DeploymentService applies resource limits around GitOperations. It is kept
// independent from webhook authentication so legacy hooks can be migrated
// without changing their authentication semantics.
type DeploymentService struct {
	gitOps                 *GitOperations
	limiter                *DeploymentLimiter
	acquireTimeout         time.Duration
	cloneTimeout           time.Duration
	maxRepositorySizeBytes int64
}

func NewDeploymentService(config *Config) *DeploymentService {
	return &DeploymentService{
		gitOps:                 NewGitOperations(config),
		limiter:                NewDeploymentLimiter(config.MaxConcurrentDeploys),
		acquireTimeout:         config.AcquireTimeout,
		cloneTimeout:           config.CloneTimeout,
		maxRepositorySizeBytes: config.MaxRepositorySizeMB * 1024 * 1024,
	}
}

func (s *DeploymentService) Deploy(ctx context.Context, repo VerifiedRepository, target SiteTarget) error {
	if s == nil || s.gitOps == nil || s.limiter == nil {
		return errors.New("deployment service is not configured")
	}
	if repo.SizeBytes > s.maxRepositorySizeBytes {
		return fmt.Errorf("%w: %d bytes exceeds %d bytes", ErrRepositoryTooLarge, repo.SizeBytes, s.maxRepositorySizeBytes)
	}
	release, err := s.acquire(ctx, target.Path())
	if err != nil {
		return err
	}
	defer release()
	cloneCtx, cancel := context.WithTimeout(ctx, s.cloneTimeout)
	defer cancel()
	return s.gitOps.Deploy(cloneCtx, repo, target)
}

func (s *DeploymentService) Remove(ctx context.Context, target SiteTarget) error {
	if s == nil || s.gitOps == nil || s.limiter == nil {
		return errors.New("deployment service is not configured")
	}
	release, err := s.acquire(ctx, target.Path())
	if err != nil {
		return err
	}
	defer release()
	return s.gitOps.RemoveSite(target)
}

func (s *DeploymentService) acquire(ctx context.Context, target string) (func(), error) {
	acquireCtx, cancel := context.WithTimeout(ctx, s.acquireTimeout)
	defer cancel()
	release, err := s.limiter.Acquire(acquireCtx, target)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("%w: %w", ErrDeploymentSaturated, err)
		}
		return nil, err
	}
	return release, nil
}
