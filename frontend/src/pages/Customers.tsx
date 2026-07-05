import { Box, Button, Card, CardContent, Typography } from '@mui/material'

export function Customers() {
  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Customers
      </Typography>
      <Card>
        <CardContent>
          <Button variant="contained">Add Customer</Button>
          <Typography color="text.secondary" sx={{ mt: 3 }}>
            Customer management will be connected to the backend API next.
          </Typography>
        </CardContent>
      </Card>
    </Box>
  )
}
