package main

import (
	"context"
	"errors"
	"fmt"

	qurl "github.com/layervai/qurl-go/qurl"
)

// reconcileConnectorResourceDeletion proves the exact resource lifecycle
// before (and, for an outcome-unknown DELETE, after) mutation. The retained
// cache mapping is the durable retry authority; a prior DELETE may have
// committed immediately before a crash or lost response. Only an explicit
// revoked/tombstoned read state or a successful DELETE response proves that
// local cleanup may continue. A 404 is not proof under the qURL service contract:
// already-revoked resources remain addressable and DELETE returns 204, so a
// missing exact ID must preserve its local retry identity and fail closed.
//
// alreadyVerified is true only when the same explicit remove transaction just
// obtained a pending resource through the management lookup and checked its
// Connector-id/public-id tuple. Resolved cache/YAML identities always take the
// initial read path so a corrupt cross-id mapping cannot revoke another resource.
func reconcileConnectorResourceDeletion(ctx context.Context, client *qurl.Client, slug, resourceID string, alreadyVerified bool) (deletedNow bool, err error) {
	if client == nil {
		return false, errors.New("qURL resource client is nil")
	}
	if !alreadyVerified {
		resource, lookupErr := client.GetConnectorResource(ctx, resourceID)
		if connectorResourceReadProvesDeletion(lookupErr) {
			return false, nil
		}
		if lookupErr != nil {
			return false, fmt.Errorf("inspect qURL resource %s before deletion: %w", resourceID, lookupErr)
		}
		if err := validateConnectorDeletionTarget(resource, slug, resourceID); err != nil {
			return false, err
		}
	}

	deleteErr := client.DeleteConnectorResource(ctx, resourceID)
	if deleteErr == nil {
		return true, nil
	}
	if errors.Is(deleteErr, qurl.ErrConnectorResourceNotFound) {
		return false, fmt.Errorf("delete qURL resource %s returned not found; exact retry identity is preserved: %w", resourceID, deleteErr)
	}
	if !errors.Is(deleteErr, qurl.ErrConnectorResourceOutcomeUnknown) {
		return false, deleteErr
	}

	// The SDK marks post-dispatch transport/5xx/response failures outcome
	// unknown. Reconcile immediately by immutable public id; if the resource is
	// still active or the exact read returns 404, retain both the original
	// mutation error and exact local retry state rather than guessing or issuing
	// a second DELETE in this call.
	resource, lookupErr := client.GetConnectorResource(ctx, resourceID)
	if connectorResourceReadProvesDeletion(lookupErr) {
		return true, nil
	}
	if lookupErr != nil {
		return false, errors.Join(
			fmt.Errorf("delete qURL resource %s: %w", resourceID, deleteErr),
			fmt.Errorf("reconcile qURL resource %s after uncertain deletion: %w", resourceID, lookupErr),
		)
	}
	if err := validateConnectorDeletionTarget(resource, slug, resourceID); err != nil {
		return false, errors.Join(fmt.Errorf("delete qURL resource %s: %w", resourceID, deleteErr), err)
	}
	return false, fmt.Errorf("delete qURL resource %s remains unresolved and the exact resource is still active; retry state is preserved: %w", resourceID, deleteErr)
}

func connectorResourceReadProvesDeletion(err error) bool {
	return errors.Is(err, qurl.ErrConnectorResourceRevoked) ||
		errors.Is(err, qurl.ErrConnectorResourceTombstoned)
}

func validateConnectorDeletionTarget(resource *qurl.ConnectorResource, slug, resourceID string) error {
	if resource == nil {
		return errors.New("qURL service returned no Connector resource while confirming deletion target")
	}
	if resource.ResourceID != resourceID {
		return fmt.Errorf("Connector id %q resolved resource_id %q while confirming deletion target, want %q", slug, resource.ResourceID, resourceID)
	}
	if resource.Slug != slug {
		return fmt.Errorf("resource_id %q belongs to Connector id %q, not %q; refusing deletion", resourceID, resource.Slug, slug)
	}
	return nil
}
