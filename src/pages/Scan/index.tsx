import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui';
import { Grid, GridItem } from '@/components/ui/grid';

const Scan = () => {
  return (
    <div>
      <Card>
        <CardHeader>
          <CardTitle>Scan Page</CardTitle>
        </CardHeader>
        <CardContent>
          <Grid cols={2} gap={4}>
            <GridItem span={1}>
              <p>This is the scan page content.</p>
            </GridItem>
            <GridItem span={1}>
              <p>More content here.</p>
            </GridItem>
          </Grid>
        </CardContent>
      </Card>
    </div>
  );
};

export default Scan;
