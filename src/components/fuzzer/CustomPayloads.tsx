
import React, { useState } from 'react';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { FileX } from 'lucide-react';

interface Payload {
  id: string;
  content: string;
  isEditing?: boolean;
}

interface CustomPayloadsProps {
  onPayloadsChange: (payloads: string[]) => void;
}

export const CustomPayloads: React.FC<CustomPayloadsProps> = ({ onPayloadsChange }) => {
  const [payloads, setPayloads] = useState<Payload[]>([]);
  const [editingContent, setEditingContent] = useState<string>('');

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const text = await file.text();
    const newPayloads = text
      .split('\n')
      .filter(line => line.trim())
      .map(content => ({
        id: crypto.randomUUID(),
        content: content.trim(),
      }));

    setPayloads(prev => [...prev, ...newPayloads]);
    onPayloadsChange([...payloads, ...newPayloads].map(p => p.content));
  };

  const deletePayload = (id: string) => {
    setPayloads(prev => {
      const updated = prev.filter(p => p.id !== id);
      onPayloadsChange(updated.map(p => p.content));
      return updated;
    });
  };

  const startEditing = (payload: Payload) => {
    setPayloads(prev => prev.map(p => ({
      ...p,
      isEditing: p.id === payload.id
    })));
    setEditingContent(payload.content);
  };

  const saveEdit = (id: string) => {
    setPayloads(prev => {
      const updated = prev.map(p => p.id === id ? {
        ...p,
        content: editingContent,
        isEditing: false
      } : p);
      onPayloadsChange(updated.map(p => p.content));
      return updated;
    });
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-4">
        <Input
          type="file"
          accept=".txt,.csv"
          onChange={handleFileUpload}
          className="max-w-xs"
        />
      </div>

      <ScrollArea className="h-[400px] w-full rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Payload</TableHead>
              <TableHead className="w-24">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {payloads.length === 0 ? (
              <TableRow>
                <TableCell colSpan={2} className="text-center text-muted-foreground">
                  No payloads uploaded yet. Upload a .txt or .csv file to begin.
                </TableCell>
              </TableRow>
            ) : (
              payloads.map(payload => (
                <TableRow key={payload.id}>
                  <TableCell>
                    {payload.isEditing ? (
                      <Input
                        value={editingContent}
                        onChange={(e) => setEditingContent(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && saveEdit(payload.id)}
                      />
                    ) : (
                      <span className="font-mono">{payload.content}</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      {payload.isEditing ? (
                        <Button size="sm" onClick={() => saveEdit(payload.id)}>Save</Button>
                      ) : (
                        <Button size="sm" variant="outline" onClick={() => startEditing(payload)}>
                          Edit
                        </Button>
                      )}
                      <Button 
                        size="sm" 
                        variant="destructive" 
                        onClick={() => deletePayload(payload.id)}
                      >
                        <FileX className="h-4 w-4" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </ScrollArea>
    </div>
  );
};
