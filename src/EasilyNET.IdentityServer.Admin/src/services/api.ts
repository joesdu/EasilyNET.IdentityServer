import { request } from '@umijs/max';

// ================== Types ==================

export interface SecretInput {
  value: string;
  description?: string;
  type?: string;
}

export interface Client {
  id: number;
  clientId: string;
  clientName?: string;
  description?: string;
  enabled: boolean;
  clientType: number;
  requirePkce: boolean;
  requireClientSecret: boolean;
  requireConsent: boolean;
  accessTokenLifetime: number;
  refreshTokenLifetime: number;
  authorizationCodeLifetime?: number;
  allowedGrantTypes: string[];
  allowedScopes: string[];
  redirectUris: string[];
  allowedCorsOrigins?: string[];
  claims?: { type: string; value: string }[];
  properties?: { key: string; value: string }[];
  clientUri?: string;
  logoUri?: string;
  userCodeType?: string;
  deviceCodeLifetime?: number;
  allowPlainTextPkce?: boolean;
  allowRememberConsent?: boolean;
}

export interface CreateClientRequest {
  clientId: string;
  clientName?: string;
  description?: string;
  enabled: boolean;
  clientType: number;
  requirePkce: boolean;
  requireClientSecret: boolean;
  requireConsent: boolean;
  allowPlainTextPkce?: boolean;
  allowRememberConsent?: boolean;
  accessTokenLifetime: number;
  refreshTokenLifetime: number;
  authorizationCodeLifetime?: number;
  deviceCodeLifetime?: number;
  allowedGrantTypes: string[];
  allowedScopes: string[];
  redirectUris: string[];
  allowedCorsOrigins?: string[];
  clientUri?: string;
  logoUri?: string;
  clientSecrets?: SecretInput[];
}

export interface UpdateClientRequest extends Omit<CreateClientRequest, 'clientId'> {}

export interface ApiResource {
  id: number;
  name: string;
  displayName?: string;
  description?: string;
  enabled: boolean;
  scopes: string[];
  userClaims: string[];
  apiSecrets?: SecretInput[];
  properties?: { key: string; value: string }[];
}

export interface CreateApiResourceRequest {
  name: string;
  displayName?: string;
  description?: string;
  enabled: boolean;
  scopes: string[];
  userClaims: string[];
}

export interface ApiScope {
  id: number;
  name: string;
  displayName?: string;
  description?: string;
  enabled: boolean;
  required: boolean;
  emphasize: boolean;
  userClaims: string[];
}

export interface CreateApiScopeRequest {
  name: string;
  displayName?: string;
  description?: string;
  enabled: boolean;
  required: boolean;
  emphasize: boolean;
  userClaims: string[];
}

export interface IdentityResource {
  id: number;
  name: string;
  displayName?: string;
  description?: string;
  enabled: boolean;
  required: boolean;
  emphasize: boolean;
  showInDiscoveryDocument: boolean;
  userClaims: string[];
}

export interface CreateIdentityResourceRequest {
  name: string;
  displayName?: string;
  description?: string;
  enabled: boolean;
  required: boolean;
  emphasize: boolean;
  showInDiscoveryDocument: boolean;
  userClaims: string[];
}

// ================== Clients API ==================

export async function getClients(): Promise<Client[]> {
  return request<Client[]>('/api/clients');
}

export async function getClient(id: number): Promise<Client> {
  return request<Client>(`/api/clients/${id}`);
}

export async function createClient(data: CreateClientRequest): Promise<{ id: number; clientId: string }> {
  return request('/api/clients', { method: 'POST', data });
}

export async function updateClient(id: number, data: UpdateClientRequest): Promise<void> {
  return request(`/api/clients/${id}`, { method: 'PUT', data });
}

export async function deleteClient(id: number): Promise<void> {
  return request(`/api/clients/${id}`, { method: 'DELETE' });
}

// ================== API Resources API ==================

export async function getApiResources(): Promise<Omit<ApiResource, 'apiSecrets' | 'properties'>[]> {
  return request('/api/apiresources');
}

export async function getApiResource(id: number): Promise<ApiResource> {
  return request<ApiResource>(`/api/apiresources/${id}`);
}

export async function createApiResource(data: CreateApiResourceRequest): Promise<{ id: number; name: string }> {
  return request('/api/apiresources', { method: 'POST', data });
}

export async function updateApiResource(id: number, data: CreateApiResourceRequest): Promise<void> {
  return request(`/api/apiresources/${id}`, { method: 'PUT', data });
}

export async function deleteApiResource(id: number): Promise<void> {
  return request(`/api/apiresources/${id}`, { method: 'DELETE' });
}

// ================== API Scopes API ==================

export async function getApiScopes(): Promise<ApiScope[]> {
  return request<ApiScope[]>('/api/apiscopes');
}

export async function getApiScope(id: number): Promise<ApiScope> {
  return request<ApiScope>(`/api/apiscopes/${id}`);
}

export async function createApiScope(data: CreateApiScopeRequest): Promise<{ id: number; name: string }> {
  return request('/api/apiscopes', { method: 'POST', data });
}

export async function updateApiScope(id: number, data: CreateApiScopeRequest): Promise<void> {
  return request(`/api/apiscopes/${id}`, { method: 'PUT', data });
}

export async function deleteApiScope(id: number): Promise<void> {
  return request(`/api/apiscopes/${id}`, { method: 'DELETE' });
}

// ================== Identity Resources API ==================

export async function getIdentityResources(): Promise<IdentityResource[]> {
  return request<IdentityResource[]>('/api/identityresources');
}

export async function getIdentityResource(id: number): Promise<IdentityResource> {
  return request<IdentityResource>(`/api/identityresources/${id}`);
}

export async function createIdentityResource(data: CreateIdentityResourceRequest): Promise<{ id: number; name: string }> {
  return request('/api/identityresources', { method: 'POST', data });
}

export async function updateIdentityResource(id: number, data: CreateIdentityResourceRequest): Promise<void> {
  return request(`/api/identityresources/${id}`, { method: 'PUT', data });
}

export async function deleteIdentityResource(id: number): Promise<void> {
  return request(`/api/identityresources/${id}`, { method: 'DELETE' });
}
