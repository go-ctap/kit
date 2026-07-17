package session

import (
	"slices"
	"sync"

	"github.com/go-ctap/ctap/protocol"
	rtruntime "github.com/go-ctap/kit/internal/runtime"
	"github.com/go-ctap/kit/internal/secret"
	appconfig "github.com/go-ctap/kit/model/config"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
)

type TokenKey = rtruntime.TokenKey

type Cache struct {
	mu sync.Mutex

	credentialInventory *appcredentials.InventoryReport
	largeBlobLists      *applargeblobs.ListReport
	configStatus        *appconfig.StatusReport
	tokenKey            TokenKey
	tokenSecret         *secret.Handle
}

func NewCache() Cache {
	return Cache{}
}

func (c *Cache) InvalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.wipeCredentialInventoryLocked()

	c.largeBlobLists = nil
	c.configStatus = nil
	c.invalidateTokensLocked()
}

func (c *Cache) InvalidateCredentials() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.wipeCredentialInventoryLocked()

	c.largeBlobLists = nil
}

func (c *Cache) InvalidateLargeBlobs() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.largeBlobLists = nil
}

func (c *Cache) InvalidateConfig() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.configStatus = nil
}

func (c *Cache) Credential() (appcredentials.InventoryReport, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.credentialInventory == nil {
		return appcredentials.InventoryReport{}, false
	}

	return cloneCredentialReport(*c.credentialInventory), true
}

func (c *Cache) SetCredential(report appcredentials.InventoryReport) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.wipeCredentialInventoryLocked()
	c.largeBlobLists = nil

	cloned := cloneCredentialReport(report)
	c.credentialInventory = &cloned
}

func (c *Cache) LargeBlobList() (applargeblobs.ListReport, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.largeBlobLists == nil {
		return applargeblobs.ListReport{}, false
	}

	return *c.largeBlobLists, true
}

func (c *Cache) SetLargeBlobList(report applargeblobs.ListReport) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.largeBlobLists = &report
}

func (c *Cache) Config() (appconfig.StatusReport, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.configStatus == nil {
		return appconfig.StatusReport{}, false
	}

	return *c.configStatus, true
}

func (c *Cache) SetConfig(report appconfig.StatusReport) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.configStatus = &report
}

func (c *Cache) GetToken(key TokenKey) ([]byte, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.tokenSecret == nil || !c.tokenKey.Covers(key) {
		return nil, false, nil
	}

	token, err := c.tokenSecret.Bytes()
	if err != nil {
		c.tokenKey = TokenKey{}
		c.tokenSecret = nil

		return nil, false, err
	}

	return token, true, nil
}

func (c *Cache) SetToken(key TokenKey, token *secret.Handle) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.invalidateTokensLocked()
	c.tokenKey = key
	c.tokenSecret = token
}

func (c *Cache) InvalidateToken() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.invalidateTokensLocked()
}

func (c *Cache) InvalidateTokenUnlessPermission(permission protocol.Permission) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.tokenSecret == nil {
		return
	}
	if permission == protocol.PermissionPersistentCredentialManagementReadOnly &&
		c.tokenKey.Permission != permission {
		c.invalidateTokensLocked()

		return
	}

	remaining := c.tokenKey.Permission & permission
	if remaining == protocol.PermissionNone {
		c.invalidateTokensLocked()

		return
	}

	c.tokenKey.Permission = remaining
	if !permissionUsesRPID(remaining) {
		c.tokenKey.RPID = ""
	}
}

func permissionUsesRPID(permission protocol.Permission) bool {
	return permission&(protocol.PermissionMakeCredential|
		protocol.PermissionGetAssertion|
		protocol.PermissionCredentialManagement) != 0
}

func (c *Cache) invalidateTokensLocked() {
	if c.tokenSecret == nil {
		return
	}

	c.tokenKey = TokenKey{}
	c.tokenSecret.Invalidate()
	c.tokenSecret = nil
}

func (c *Cache) wipeCredentialInventoryLocked() {
	if c.credentialInventory == nil {
		return
	}

	wipeCredentialReport(c.credentialInventory)
	c.credentialInventory = nil
}

func cloneCredentialReport(report appcredentials.InventoryReport) appcredentials.InventoryReport {
	cloned := report
	if len(report.Groups) > 0 {
		cloned.Groups = make([]appcredentials.CredentialGroup, len(report.Groups))
	}

	for groupIndex, group := range report.Groups {
		clonedGroup := group
		if len(group.Credentials) > 0 {
			clonedGroup.Credentials = make([]appcredentials.CredentialRecord, len(group.Credentials))
		}

		for credentialIndex, record := range group.Credentials {
			clonedRecord := record
			clonedRecord.CredentialTransports = slices.Clone(record.CredentialTransports)
			clonedRecord.LargeBlobKey = slices.Clone(record.LargeBlobKey)
			clonedGroup.Credentials[credentialIndex] = clonedRecord
		}

		cloned.Groups[groupIndex] = clonedGroup
	}

	return cloned
}

func wipeCredentialReport(report *appcredentials.InventoryReport) {
	for groupIndex := range report.Groups {
		for credentialIndex := range report.Groups[groupIndex].Credentials {
			secret.Zero(report.Groups[groupIndex].Credentials[credentialIndex].LargeBlobKey)
			report.Groups[groupIndex].Credentials[credentialIndex].LargeBlobKey = nil
		}
	}
}
