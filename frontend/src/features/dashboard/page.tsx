import { Box, Card, CardContent, Typography } from '@mui/material'

const stats = [
  { label: 'Customers', value: 0 },
  { label: 'Assets', value: 0 },
  { label: 'Critical', value: 0 },
  { label: 'High', value: 0 },
]

export function Dashboard() {
  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Dashboard
      </Typography>
      <Typography color="text.secondary" sx={{ mb: 4 }}>
        Security exposure overview for managed customers and assets.
      </Typography>

      <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 3, mb: 3 }}>
        {stats.map((stat) => (
          <Card key={stat.label}>
            <CardContent>
              <Typography color="text.secondary">{stat.label}</Typography>
              <Typography variant="h3">{stat.value}</Typography>
            </CardContent>
          </Card>
        ))}
      </Box>

      <Box sx={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 3 }}>
        <Card>
          <CardContent>
            <Typography variant="h6">Risk Overview</Typography>
            <Typography color="text.secondary" sx={{ mt: 2 }}>
              Charts will appear here once findings are available.
            </Typography>
          </CardContent>
        </Card>

        <Card>
          <CardContent>
            <Typography variant="h6">Recent Activity</Typography>
            <Typography color="text.secondary" sx={{ mt: 2 }}>
              No scans yet.
            </Typography>
          </CardContent>
        </Card>
      </Box>
    </Box>
  )
}
