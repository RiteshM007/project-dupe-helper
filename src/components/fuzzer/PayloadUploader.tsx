
import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Upload } from 'lucide-react';
import { toast } from '@/hooks/use-toast';

interface PayloadUploaderProps {
  onPayloadsUploaded: (payloads: string[]) => void;
}

export const PayloadUploader: React.FC<PayloadUploaderProps> = ({ onPayloadsUploaded }) => {
  const [isOpen, setIsOpen] = useState(false);

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    
    if (!file.name.endsWith('.txt')) {
      toast({
        title: "Invalid File",
        description: "Please upload a .txt file",
        variant: "destructive",
      });
      return;
    }

    try {
      const text = await file.text();
      const payloads = text
        .split('\n')
        .map(line => line.trim())
        .filter(line => line.length > 0);
      
      if (payloads.length === 0) {
        toast({
          title: "Empty File",
          description: "The payload file is empty",
          variant: "destructive",
        });
        return;
      }

      onPayloadsUploaded(payloads);
      setIsOpen(false);
      toast({
        title: "Payloads Uploaded",
        description: `${payloads.length} payloads loaded successfully`,
      });
    } catch (error) {
      toast({
        title: "Upload Error",
        description: "Failed to read payload file",
        variant: "destructive",
      });
    }
  };

  return (
    <>
      <Button onClick={() => setIsOpen(true)} variant="outline">
        <Upload className="mr-2 h-4 w-4" />
        Upload Custom Payloads
      </Button>

      <Dialog open={isOpen} onOpenChange={setIsOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Upload Payloads</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Upload a .txt file containing your custom payloads (one per line)
            </p>
            <Input
              type="file"
              accept=".txt"
              onChange={handleFileUpload}
              className="w-full"
            />
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
};
