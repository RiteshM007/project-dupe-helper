
import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Upload } from 'lucide-react';
import { toast } from '@/hooks/use-toast';
import { Badge } from '@/components/ui/badge';

interface PayloadUploaderProps {
  onPayloadsUploaded: (payloads: string[]) => void;
}

export const PayloadUploader: React.FC<PayloadUploaderProps> = ({ onPayloadsUploaded }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      if (!file.name.endsWith('.txt')) {
        toast({
          title: "Invalid File",
          description: "Please upload a .txt file",
          variant: "destructive",
        });
        return;
      }
      setSelectedFile(file);
    }
  };

  const handleFileUpload = async () => {
    if (!selectedFile) return;
    
    try {
      const text = await selectedFile.text();
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
      setSelectedFile(null);
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
      <Button onClick={() => setIsOpen(true)} variant="outline" className="group">
        <Upload className="mr-2 h-4 w-4 transition-all group-hover:scale-110" />
        Upload Custom Payloads
      </Button>

      <Dialog open={isOpen} onOpenChange={setIsOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Upload Payloads</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Upload a .txt file containing your custom payloads (one per line)
            </p>
            
            <div className="flex flex-col gap-4">
              <Input
                type="file"
                accept=".txt"
                onChange={handleFileSelect}
                className="w-full"
              />
              
              {selectedFile && (
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className="text-xs">
                    {selectedFile.name}
                  </Badge>
                  <span className="text-xs text-muted-foreground">
                    {(selectedFile.size / 1024).toFixed(2)} KB
                  </span>
                </div>
              )}
            </div>
            
            <div className="flex justify-end">
              <Button 
                onClick={handleFileUpload}
                disabled={!selectedFile}
              >
                Upload Payloads
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
};
