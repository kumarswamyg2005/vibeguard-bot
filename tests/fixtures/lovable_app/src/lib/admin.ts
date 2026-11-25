// TODO: move to server
const SERVICE_KEY = 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJpc3MiOiAic3VwYWJhc2UiLCAicmVmIjogImRlbW9hcHAiLCAicm9sZSI6ICJzZXJ2aWNlX3JvbGUiLCAiaWF0IjogMTcwMDAwMDAwMCwgImV4cCI6IDIwMDAwMDAwMDB9.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
export function adminDelete(userId: string) {
  return fetch('/rest/v1/profiles', { headers: { apikey: SERVICE_KEY } })
}
