
import React from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Upload } from 'lucide-react';
import { toast } from '@/hooks/use-toast';

interface PayloadUploaderProps {
  onPayloadsUploaded: (payloads: string[]) => void;
}

export const PayloadUploader: React.FC<PayloadUploaderProps> = ({ onPayloadsUploaded }) => {
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
    <div className="flex items-center gap-4">
      <Input
        type="file"
        accept=".txt"
        onChange={handleFileUpload}
        className="max-w-xs"
      />
      <Button variant="outline">
        <Upload className="mr-2 h-4 w-4" />
        Upload Payloads
      </Button>
    </div>
  );
};
