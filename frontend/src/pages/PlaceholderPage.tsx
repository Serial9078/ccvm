import { Box, Card, CardContent, Typography } from '@mui/material'

export function PlaceholderPage({ title }: { title: string }) {
  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        {title}
      </Typography>
      <Card>
        <CardContent>
          <Typography color="text.secondary">
            This module is prepared for the next sprint.
          </Typography>
        </CardContent>
      </Card>
    </Box>
  )
}
