package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	qurl "github.com/layervai/qurl-go/qurl"
	"github.com/spf13/cobra"

	"github.com/layervai/qurl-connector/pkg/agentstate"
	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

var removeResourceID string

func getResourceSDKOrigin(versionedBase string) (string, error) {
	u, err := url.Parse(versionedBase)
	if err != nil {
		return "", fmt.Errorf("parse qURL resource API URL: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.Opaque != "" {
		return "", errors.New("qURL resource API URL must be an absolute http or https URL with a host")
	}
	// url.Parse does not distinguish an absent fragment delimiter from an empty
	// one, so the literal check keeps https://host/v1# fail closed as well.
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(versionedBase, "#") || u.User != nil {
		return "", errors.New("qURL resource API URL must not contain userinfo, query, or fragment")
	}
	path := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/v1")
	u.Path = path
	u.RawPath = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func init() {
	removeCmd.Flags().StringVar(&removeResourceID, "resource-id", "", "remove the route with this qURL resource_id instead of the positional route id")
}

var removeCmd = &cobra.Command{
	Use:   "remove [id]",
	Short: "Remove a service route",
	Long: `Remove a service route from the configuration by route id or resource ID.

Examples:
  qurl-connector remove my-app
  qurl-connector remove --resource-id "$RESOURCE_PUBLIC_KEY"`,
	Args: cobra.MaximumNArgs(1),
	RunE: runRemove,
}

func runRemove(cmd *cobra.Command, args []string) error {
	id := ""
	if len(args) > 0 {
		id = args[0]
	}

	if id == "" && removeResourceID == "" {
		return fmt.Errorf("provide a route id as argument or use --resource-id flag")
	}

	cfgPath, discoverErr := nhpconfig.Discover(cfgFile)
	if discoverErr != nil {
		return fmt.Errorf("no qurl-proxy.yaml found; use 'qurl-connector add' to create one or --config to specify the path")
	}
	canonicalConfigPath, err := nhpconfig.CanonicalPath(cfgPath)
	if err != nil {
		return fmt.Errorf("resolving config path: %w", err)
	}
	cfgPath = canonicalConfigPath

	ctx := commandContext(cmd)

	configAccess, err := acquireConnectorRunConfigAccess(ctx, cfgPath)
	if err != nil {
		return err
	}
	cfg := configAccess.config
	configTxn := configAccess.transaction
	stateDir := agentstate.ResolveDir("")
	removeErr := withRemoveConnectorIdentityCache(ctx, stateDir, func(txnCtx context.Context, txn *connectorIdentityCacheTxn) error {
		// A read-only config snapshot has no local commit path to retain. Once
		// the state-cache lock is held, release and fully revalidate the pinned
		// snapshot before any cached-only remote cleanup can begin.
		if configAccess.snapshot != nil {
			if err := configAccess.Close(); err != nil {
				return fmt.Errorf("release immutable config after state-lock handoff: %w", err)
			}
		}
		return removeConnectorSelection(txnCtx, cfg, configTxn, txn, id, removeResourceID, configAccess.writeErr)
	})
	return errors.Join(removeErr, configAccess.Close())
}

// withRemoveConnectorIdentityCache treats an absent state directory as a
// proven-empty cache. This keeps a never-provisioned local route removable on a
// fresh host without requiring permission to create /var/lib/layerv/agent.
// Existing state still takes the full secure cache lock and validation path.
func withRemoveConnectorIdentityCache(ctx context.Context, stateDir string, fn func(context.Context, *connectorIdentityCacheTxn) error) error {
	_, err := os.Lstat(stateDir)
	switch {
	case err == nil:
		return withConnectorIdentityCacheLockContext(ctx, stateDir, fn)
	case errors.Is(err, os.ErrNotExist):
		return fn(ctx, nil)
	default:
		return fmt.Errorf("inspect Connector state directory before removal: %w", err)
	}
}

func removeConnectorSelection(ctx context.Context, cfg *nhpconfig.Config, configTxn *nhpconfig.FileTransaction, txn *connectorIdentityCacheTxn, id, resourceID string, configWriteErr error) error {
	cache := &connectorIdentityCache{
		byID: make(map[string]connectorIdentityCacheEntry), pending: make(map[string]connectorIdentityPendingRequest),
	}
	if txn != nil {
		if err := ensureConnectorIdentityCacheInitializedLocked(txn); err != nil {
			return err
		}
		var err error
		cache, err = loadConnectorIdentityCacheUnlocked(txn)
		if err != nil {
			return err
		}
	}
	selection, err := selectConnectorRemoval(cfg, cache, id, resourceID)
	if err != nil {
		return err
	}
	if configWriteErr != nil && selection.routeIndex >= 0 {
		return fmt.Errorf("config is not writable; no qURL resource was changed: edit the host-side YAML to remove Connector id %q, then rerun `qurl-connector remove %s` to revoke its retained cached identity: %w", selection.id, selection.id, configWriteErr)
	}

	needsRemoteRemoval := selection.resourceID != "" || selection.pending
	if needsRemoteRemoval {
		if txn == nil {
			return fmt.Errorf("Connector id %q has a resource identity but native device state is absent; local route is preserved", selection.id)
		}
		remoteErr := withRegisteredConnectorResourceClient(ctx, cfg.QURL.APIURL, txn, cache, func(client *qurl.Client, continuity connectorStateContinuity) error {
			transactionContinuity := connectorIdentityTransactionContinuity{sdk: continuity, txn: txn}
			resourceVerified := false
			if selection.pending && selection.resourceID == "" {
				resource, lookupErr := gateConnectorStateResult(transactionContinuity, "inspect pending Connector resource by id before removal", func() (*qurl.ConnectorResource, error) {
					return client.GetConnectorResourceBySlug(ctx, selection.id)
				})
				if errors.Is(lookupErr, qurl.ErrConnectorResourceNotFound) {
					return nil
				}
				if lookupErr != nil {
					return fmt.Errorf("inspect pending Connector id %q before removal; exact NHP retry state preserved: %w", selection.id, lookupErr)
				}
				if resource == nil || resource.Slug != selection.id {
					return fmt.Errorf("pending Connector id %q returned an inconsistent management binding; exact NHP retry state preserved", selection.id)
				}
				selection.resourceID = resource.ResourceID
				resourceVerified = true
				if err := gateConnectorStateContinuity(transactionContinuity, "persist reconciled Connector identity before removal", func() error {
					return cache.recordResolutionLocked(txn, selection.id, resource)
				}); err != nil {
					return fmt.Errorf("persist reconciled Connector identity before remote deletion: %w", err)
				}
			}
			if selection.resourceID == "" {
				return nil
			}
			if !resourceVerified {
				resource, lookupErr := gateConnectorStateResult(transactionContinuity, "inspect exact Connector resource before deletion", func() (*qurl.ConnectorResource, error) {
					return client.GetConnectorResource(ctx, selection.resourceID)
				})
				if connectorResourceReadProvesDeletion(lookupErr) {
					fmt.Printf("qURL resource already absent (resource_id: %s)\n", selection.resourceID)
					return nil
				}
				if lookupErr != nil {
					return fmt.Errorf("inspect qURL resource %s before deletion: %w", selection.resourceID, lookupErr)
				}
				if err := validateConnectorDeletionTarget(resource, selection.id, selection.resourceID); err != nil {
					return err
				}
				if err := gateConnectorStateContinuity(transactionContinuity, "persist exact management binding before removal", func() error {
					return cache.recordResolutionLocked(txn, selection.id, resource)
				}); err != nil {
					return fmt.Errorf("persist exact Connector identity before remote deletion: %w", err)
				}
				resourceVerified = true
			}
			deletedNow, apiErr := gateConnectorStateResult(transactionContinuity, "delete exact Connector resource", func() (bool, error) {
				return reconcileConnectorResourceDeletion(ctx, client, selection.id, selection.resourceID, resourceVerified)
			})
			if apiErr != nil {
				return fmt.Errorf("delete qURL resource %s; exact identity retained for safe retry: %w", selection.resourceID, apiErr)
			}
			if deletedNow {
				fmt.Printf("Deleted from qURL API (resource_id: %s)\n", selection.resourceID)
			} else {
				fmt.Printf("qURL resource already absent (resource_id: %s)\n", selection.resourceID)
			}
			return nil
		})
		if remoteErr != nil {
			if selection.routeIndex >= 0 {
				return fmt.Errorf("registered device state or resource operation unavailable; local route and retained qURL resource identity are preserved: %w", remoteErr)
			}
			return fmt.Errorf("registered device state or resource operation unavailable; the host route is already absent but its retained qURL resource identity still requires cleanup: %w", remoteErr)
		}
	}

	// The exact identity is durable before DELETE. If a later atomic YAML save
	// fails or the process crashes, a remaining route reopens only that revoked
	// public ID and therefore fails closed instead of provisioning a replacement.
	if selection.routeIndex >= 0 {
		if txn != nil {
			if err := validateConnectorIdentityCacheNamespace(txn); err != nil {
				return fmt.Errorf("validate Connector identity continuity before local route commit: %w", err)
			}
		}
		removed := cfg.Routes[selection.routeIndex]
		cfg.Routes = append(cfg.Routes[:selection.routeIndex], cfg.Routes[selection.routeIndex+1:]...)
		if configTxn == nil {
			return errors.New("config transaction is unavailable after remote deletion; exact identity retained for safe retry")
		}
		if err := configTxn.Save(cfg); err != nil {
			return fmt.Errorf("saving config after remote deletion; exact identity retained for safe retry: %w", err)
		}
		fmt.Printf("Removed route %q (%s)\n", selection.id, removed.Type)
		fmt.Printf("Config saved to %s\n", configTxn.Path())
	}

	if txn != nil {
		if err := cache.removeLocked(txn, selection.id); err != nil {
			return fmt.Errorf("prune deleted Connector identity %q from cache; retry remove to complete cleanup: %w", selection.id, err)
		}
	}
	if selection.routeIndex < 0 {
		fmt.Printf("Removed cached Connector identity %q\n", selection.id)
	}
	return nil
}

func withRegisteredConnectorResourceClient(
	ctx context.Context,
	configuredAPIURL string,
	txn *connectorIdentityCacheTxn,
	cache *connectorIdentityCache,
	fn func(*qurl.Client, connectorStateContinuity) error,
) (retErr error) {
	if txn == nil || cache == nil {
		return errors.New("Connector resource client requires an open identity-cache transaction")
	}
	store, err := agentstate.NewSDKStore(txn.stateDir, agentstate.ConfiguredAgentID())
	if err != nil {
		return err
	}
	defer func() {
		retErr = errors.Join(retErr, store.Close())
	}()
	stateStore, err := store.Handoff()
	if err != nil {
		return err
	}
	origin, err := getResourceSDKOrigin(getAPIBaseURL(configuredAPIURL))
	if err != nil {
		return err
	}
	return withRegisteredConnectorResourceState(
		ctx,
		txn,
		cache,
		stateStore,
		store,
		origin,
		fn,
	)
}

type registeredConnectorResourceClient struct {
	client  *qurl.Client
	agentID string
}

// withRegisteredConnectorResourceState opens the client and obtains its
// authoritative agent id from one completed-state snapshot. The returned id is
// checked or durably bound before fn can issue the first resource request.
func withRegisteredConnectorResourceState(
	ctx context.Context,
	txn *connectorIdentityCacheTxn,
	cache *connectorIdentityCache,
	stateStore qurl.AgentStateStore,
	sdkContinuity connectorStateContinuity,
	origin string,
	fn func(*qurl.Client, connectorStateContinuity) error,
) error {
	if txn == nil || cache == nil || stateStore == nil || fn == nil {
		return errors.New("Connector resource client state is incomplete")
	}
	continuity := connectorIdentityTransactionContinuity{sdk: sdkContinuity, txn: txn}
	opened, err := gateConnectorStateResult(continuity, "open registered resource client from exact native identity", func() (*registeredConnectorResourceClient, error) {
		client, agentID, openErr := qurl.OpenRegisteredAgentWithIdentity(
			ctx,
			stateStore,
			qurl.WithAgentClientBaseURL(origin),
		)
		if openErr != nil {
			return nil, openErr
		}
		return &registeredConnectorResourceClient{client: client, agentID: agentID}, nil
	})
	if err != nil {
		return err
	}
	if opened == nil || opened.client == nil {
		return errors.New("qurl-go returned no registered resource client")
	}
	actualAgentID := opened.agentID
	if cache.agentID == "" {
		if len(cache.byID) != 0 || len(cache.pending) != 0 {
			return errors.New("unbound Connector identity cache contains continuity state")
		}
		if err := gateConnectorStateContinuity(continuity, "durably bind empty Connector identity cache before removal", func() error {
			return cache.bindAgentIDLocked(txn, actualAgentID)
		}); err != nil {
			return fmt.Errorf("bind Connector identity cache to registered device before removal: %w", err)
		}
	} else if actualAgentID != cache.agentID {
		return fmt.Errorf("Connector identity cache agent_id %s does not match native-state agent_id %s; refusing cross-device resource use", cachedAgentIDFingerprint(cache.agentID), cachedAgentIDFingerprint(actualAgentID))
	}
	if err := continuity.ValidateContinuity(); err != nil {
		return fmt.Errorf("validate registered device state before resource operation: %w", err)
	}
	return fn(opened.client, continuity)
}

type connectorRemovalSelection struct {
	id         string
	resourceID string
	routeIndex int
	pending    bool
}

func selectConnectorRemoval(cfg *nhpconfig.Config, cache *connectorIdentityCache, id, resourceID string) (connectorRemovalSelection, error) {
	if cfg == nil || cache == nil {
		return connectorRemovalSelection{}, errors.New("Connector removal state is incomplete")
	}
	if id != "" {
		if err := nhpconfig.ValidateSlug(id); err != nil {
			return connectorRemovalSelection{}, fmt.Errorf("invalid Connector id: %w", err)
		}
	}
	if resourceID != "" {
		if err := validateCachedConnectorResourceID(resourceID); err != nil {
			return connectorRemovalSelection{}, fmt.Errorf("invalid --resource-id: %w", err)
		}
	}

	fallbackID := routeIDEnvFallback()
	byID := make(map[string]connectorRemovalSelection, len(cfg.Routes)+len(cache.byID))
	byResource := make(map[string]string, len(cfg.Routes)+len(cache.byID))
	for i, route := range cfg.Routes {
		routeID := routeIDWithFallback(cfg, route, fallbackID)
		if err := nhpconfig.ValidateSlug(routeID); err != nil {
			return connectorRemovalSelection{}, fmt.Errorf("routes[%d]: invalid Connector id: %w", i, err)
		}
		if _, duplicate := byID[routeID]; duplicate {
			return connectorRemovalSelection{}, fmt.Errorf("duplicate Connector id %q", routeID)
		}
		cachedResourceID, cached := cache.resourceID(routeID)
		if route.ResourceID != "" && cached && route.ResourceID != cachedResourceID {
			return connectorRemovalSelection{}, fmt.Errorf("route %q: pinned resource_id %q conflicts with cached resource_id %q", routeID, route.ResourceID, cachedResourceID)
		}
		effectiveResourceID := route.ResourceID
		if effectiveResourceID == "" {
			effectiveResourceID = cachedResourceID
		}
		if effectiveResourceID != "" {
			if err := validateCachedConnectorResourceID(effectiveResourceID); err != nil {
				return connectorRemovalSelection{}, fmt.Errorf("route %q: invalid resource_id: %w", routeID, err)
			}
		}
		selection := connectorRemovalSelection{id: routeID, resourceID: effectiveResourceID, routeIndex: i, pending: cache.isPending(routeID)}
		byID[routeID] = selection
		if effectiveResourceID != "" {
			if owner, duplicate := byResource[effectiveResourceID]; duplicate {
				return connectorRemovalSelection{}, fmt.Errorf("Connector ids %q and %q resolve to duplicate resource_id %q", owner, routeID, effectiveResourceID)
			}
			byResource[effectiveResourceID] = routeID
		}
	}
	for cachedID, binding := range cache.byID {
		if _, configured := byID[cachedID]; configured {
			continue
		}
		cachedResourceID := binding.ResourceID
		if owner, duplicate := byResource[cachedResourceID]; duplicate {
			return connectorRemovalSelection{}, fmt.Errorf("Connector ids %q and %q resolve to duplicate resource_id %q", owner, cachedID, cachedResourceID)
		}
		byID[cachedID] = connectorRemovalSelection{id: cachedID, resourceID: cachedResourceID, routeIndex: -1}
		byResource[cachedResourceID] = cachedID
	}
	for pendingID := range cache.pending {
		if selection, configured := byID[pendingID]; configured {
			selection.pending = true
			byID[pendingID] = selection
			continue
		}
		byID[pendingID] = connectorRemovalSelection{id: pendingID, routeIndex: -1, pending: true}
	}

	var byIDSelection connectorRemovalSelection
	idFound := false
	if id != "" {
		byIDSelection, idFound = byID[id]
		if !idFound {
			return connectorRemovalSelection{}, fmt.Errorf("no route or cached Connector identity found with id %q", id)
		}
	}
	var byResourceSelection connectorRemovalSelection
	resourceFound := false
	if resourceID != "" {
		if owner, ok := byResource[resourceID]; ok {
			byResourceSelection, resourceFound = byID[owner], true
		}
		if !resourceFound {
			return connectorRemovalSelection{}, fmt.Errorf("no route or cached Connector identity found with resource ID %q", resourceID)
		}
	}
	if id != "" && resourceID != "" && byIDSelection.id != byResourceSelection.id {
		return connectorRemovalSelection{}, fmt.Errorf("route id %q and resource ID %q refer to different Connector identities", id, resourceID)
	}
	if idFound {
		if resourceID != "" && byIDSelection.resourceID != resourceID {
			return connectorRemovalSelection{}, fmt.Errorf("route id %q is bound to resource ID %q, not %q", id, byIDSelection.resourceID, resourceID)
		}
		return byIDSelection, nil
	}
	return byResourceSelection, nil
}
