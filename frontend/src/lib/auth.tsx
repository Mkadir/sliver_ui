import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import { api, type AuthMe } from './api'

interface AuthValue {
  ready: boolean
  enabled: boolean
  authenticated: boolean
  user: string
  refresh: () => Promise<void>
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthValue>({
  ready: false,
  enabled: false,
  authenticated: true,
  user: '',
  refresh: async () => {},
  login: async () => {},
  logout: async () => {},
})

export function useAuth(): AuthValue {
  return useContext(AuthContext)
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false)
  const [enabled, setEnabled] = useState(false)
  const [authenticated, setAuthenticated] = useState(true)
  const [user, setUser] = useState('')

  const apply = useCallback((me: AuthMe) => {
    setEnabled(!!me.enabled)
    setAuthenticated(!!me.authenticated)
    setUser(me.user || '')
  }, [])

  const refresh = useCallback(async () => {
    try {
      const me = await api.authMe()
      apply(me)
    } catch {
      // If the auth endpoint is unreachable, keep the shell usable only when
      // auth is known-disabled; otherwise force the login gate.
      setEnabled(true)
      setAuthenticated(false)
      setUser('')
    } finally {
      setReady(true)
    }
  }, [apply])

  useEffect(() => {
    refresh()
  }, [refresh])

  const login = useCallback(
    async (username: string, password: string) => {
      await api.login(username, password)
      await refresh()
    },
    [refresh],
  )

  const logout = useCallback(async () => {
    try {
      await api.logout()
    } finally {
      setAuthenticated(false)
      setUser('')
      await refresh()
    }
  }, [refresh])

  return (
    <AuthContext.Provider value={{ ready, enabled, authenticated, user, refresh, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}
