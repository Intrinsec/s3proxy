/*
Copyright (c) Intrinsec 2024

SPDX-License-Identifier: AGPL-3.0-only
*/
package router

import (
	"net/http"
	"time"
)

type ThrottlingMiddleware struct {
	maxConcurrentRequests int           // Max number of concurrent requests
	throttleTimeout       time.Duration // Max wait time for a request in case of overload
	semaphore             chan struct{} // Channel to manage concurrent requests
}

// NewThrottlingMiddleware creates a new throttling middleware.
func NewThrottlingMiddleware(maxConcurrentRequests int, throttleTimeout time.Duration) *ThrottlingMiddleware {
	return &ThrottlingMiddleware{
		maxConcurrentRequests: maxConcurrentRequests,
		throttleTimeout:       throttleTimeout,
		semaphore:             make(chan struct{}, maxConcurrentRequests),
	}
}

// Throttle intercepts the request and applies throttling.
func (t *ThrottlingMiddleware) Throttle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case t.semaphore <- struct{}{}: // If a slot is available, proceed
			defer func() { <-t.semaphore }() // Release the slot when done
			next.ServeHTTP(w, r)
		case <-time.After(t.throttleTimeout): // Timeout if all slots are full
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
		}
	})
}
