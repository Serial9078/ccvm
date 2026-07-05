import { Box, Button, Card, CardContent, Typography } from '@mui/material'

export function Assets() {
  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Assets
      </Typography>
      <Card>
        <CardContent>
          <Button variant="contained">Add Asset</Button>
          <Typography color="text.secondary" sx={{ mt: 3 }}>
            Asset inventory will be connected to the backend API next.
          </Typography>
        </CardContent>
      </Card>
    </Box>
  )
}
