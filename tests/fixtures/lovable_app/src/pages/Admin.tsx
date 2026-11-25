export function AdminPanel({ user }: { user: { role: string } }) {
  const isAdmin = user.role === 'admin'
  if (!isAdmin) return null
  return <div>admin</div>
}
