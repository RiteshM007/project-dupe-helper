
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { CyberpunkScannerAnimation } from '@/components/dashboard/CyberpunkScannerAnimation';
import ScanControl from '../ScanControl';

const ScanIndex = () => {
  const navigate = useNavigate();
  
  return (
    <ScanControl />
  );
};

export default ScanIndex;
