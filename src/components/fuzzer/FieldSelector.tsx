
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { AlertTriangle, Bug } from 'lucide-react';
import { toast } from '@/hooks/use-toast';

interface FieldSelectorProps {
  isActive: boolean;
  onFieldSelected: (fieldId: string, fieldName?: string) => void;
  exploitKeyword: string;
  onExploitKeywordChange: (keyword: string) => void;
}

export const FieldSelector: React.FC<FieldSelectorProps> = ({
  isActive,
  onFieldSelected,
  exploitKeyword,
  onExploitKeywordChange,
}) => {
  const [detectedFields, setDetectedFields] = useState<Array<{ id: string; name?: string; type: string }>>([]);
  const [selectedField, setSelectedField] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);

  // Simulate field detection
  const detectFields = () => {
    setIsScanning(true);
    
    // In a real implementation, this would communicate with the headless browser
    // to detect input fields on the current page
    setTimeout(() => {
      const mockFields = [
        { id: 'username', name: 'username', type: 'text' },
        { id: 'password', name: 'password', type: 'password' },
        { id: 'email', name: 'email', type: 'email' },
        { id: 'search', name: 'q', type: 'search' },
        { id: 'comment', name: 'comment', type: 'textarea' }
      ];
      
      setDetectedFields(mockFields);
      setIsScanning(false);
      
      toast({
        title: "Fields Detected",
        description: `Found ${mockFields.length} input fields on the page`,
      });
    }, 2000);
  };

  const handleFieldSelect = (fieldId: string, fieldName?: string) => {
    setSelectedField(fieldId);
    onFieldSelected(fieldId, fieldName);
    
    toast({
      title: "Field Selected",
      description: `Selected field: ${fieldName || fieldId}`,
    });
    
    // Dispatch the field selected event for other components
    window.dispatchEvent(new CustomEvent('fieldSelected', {
      detail: {
        fieldId,
        fieldType: detectedFields.find(f => f.id === fieldId)?.type || 'text',
        fieldName
      }
    }));
  };

  return (
    <Card className="bg-card/60 backdrop-blur-sm border-slate-800/20">
      <CardHeader>
        <CardTitle className="flex items-center">
          <Bug className="h-5 w-5 mr-2" />
          Target Field Selection
        </CardTitle>
        <CardDescription>
          Select a specific field on the target website to fuzz
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!isActive ? (
          <div className="text-center p-4 bg-amber-500/10 rounded-md border border-amber-500/20">
            <AlertTriangle className="h-6 w-6 mx-auto text-amber-500 mb-2" />
            <p className="text-sm">Connect to a target URL first to enable field selection</p>
          </div>
        ) : (
          <>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-medium">Exploit Keyword</h3>
                <Badge variant="outline" className="text-xs">Triggers Fuzzing</Badge>
              </div>
              <Input
                placeholder="Enter trigger keyword (e.g., FUZZ)"
                value={exploitKeyword}
                onChange={(e) => onExploitKeywordChange(e.target.value)}
                className="font-mono"
              />
              <p className="text-xs text-muted-foreground">
                When this keyword is detected in the selected field, payloads will be injected
              </p>
            </div>
            
            <div className="flex justify-between">
              <Button
                onClick={detectFields}
                disabled={isScanning}
                variant={isScanning ? "outline" : "default"}
                className="w-full"
              >
                {isScanning ? "Scanning for Fields..." : "Detect Input Fields"}
              </Button>
            </div>
            
            {detectedFields.length > 0 && (
              <div className="space-y-2 mt-4">
                <h3 className="text-sm font-medium">Detected Fields</h3>
                <div className="grid gap-2">
                  {detectedFields.map((field) => (
                    <Button
                      key={field.id}
                      variant={selectedField === field.id ? "default" : "outline"}
                      className={`text-left justify-start ${selectedField === field.id ? 'bg-primary' : 'bg-background'}`}
                      onClick={() => handleFieldSelect(field.id, field.name)}
                    >
                      <span className="font-mono text-xs mr-2">{field.id}</span>
                      <Badge variant="outline" className="ml-auto">
                        {field.type}
                      </Badge>
                    </Button>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
};
