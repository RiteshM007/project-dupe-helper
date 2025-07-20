
-- Create table for ML training results and model information
CREATE TABLE public.ml_training_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  session_id TEXT NOT NULL,
  model_type TEXT NOT NULL DEFAULT 'classifier',
  dataset_size INTEGER NOT NULL DEFAULT 0,
  accuracy DECIMAL(5,4) NOT NULL DEFAULT 0.0,
  precision_score DECIMAL(5,4),
  recall_score DECIMAL(5,4),
  f1_score DECIMAL(5,4),
  confusion_matrix JSONB,
  classification_report JSONB,
  class_distribution JSONB,
  feature_importance JSONB,
  model_path TEXT,
  training_duration INTEGER, -- in seconds
  anomaly_detection_rate DECIMAL(5,4),
  patterns_detected INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create table for generated payloads
CREATE TABLE public.ml_payloads (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  training_result_id UUID REFERENCES public.ml_training_results(id) ON DELETE CASCADE,
  payload TEXT NOT NULL,
  vulnerability_type TEXT,
  effectiveness_score DECIMAL(5,4),
  context TEXT,
  generated_by TEXT DEFAULT 'ml_model',
  is_tested BOOLEAN DEFAULT FALSE,
  test_results JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create table for fuzzing sessions
CREATE TABLE public.fuzzing_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  session_id TEXT UNIQUE NOT NULL,
  target_url TEXT NOT NULL,
  fuzzing_type TEXT NOT NULL DEFAULT 'web_application',
  status TEXT NOT NULL DEFAULT 'pending',
  total_payloads INTEGER DEFAULT 0,
  tested_payloads INTEGER DEFAULT 0,
  vulnerabilities_found INTEGER DEFAULT 0,
  scan_duration INTEGER, -- in seconds
  started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  completed_at TIMESTAMP WITH TIME ZONE,
  configuration JSONB,
  results_summary JSONB
);

-- Create table for vulnerability findings
CREATE TABLE public.vulnerability_findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  fuzzing_session_id UUID REFERENCES public.fuzzing_sessions(id) ON DELETE CASCADE NOT NULL,
  vulnerability_type TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'medium',
  payload TEXT NOT NULL,
  target_parameter TEXT,
  response_code INTEGER,
  response_time INTEGER,
  evidence JSONB,
  remediation_suggestion TEXT,
  cvss_score DECIMAL(3,1),
  discovered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create table for threat reports
CREATE TABLE public.threat_reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  severity TEXT NOT NULL DEFAULT 'medium',
  threat_type TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'automated_scan',
  target_info JSONB,
  detection_details JSONB,
  status TEXT DEFAULT 'active',
  resolved_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Enable Row Level Security
ALTER TABLE public.ml_training_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ml_payloads ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fuzzing_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vulnerability_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.threat_reports ENABLE ROW LEVEL SECURITY;

-- Create RLS policies for ml_training_results
CREATE POLICY "Users can view their own ML training results" 
  ON public.ml_training_results FOR SELECT 
  USING (auth.uid() = user_id);

CREATE POLICY "Users can create their own ML training results" 
  ON public.ml_training_results FOR INSERT 
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own ML training results" 
  ON public.ml_training_results FOR UPDATE 
  USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own ML training results" 
  ON public.ml_training_results FOR DELETE 
  USING (auth.uid() = user_id);

-- Create RLS policies for ml_payloads
CREATE POLICY "Users can view their own ML payloads" 
  ON public.ml_payloads FOR SELECT 
  USING (auth.uid() = user_id);

CREATE POLICY "Users can create their own ML payloads" 
  ON public.ml_payloads FOR INSERT 
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own ML payloads" 
  ON public.ml_payloads FOR UPDATE 
  USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own ML payloads" 
  ON public.ml_payloads FOR DELETE 
  USING (auth.uid() = user_id);

-- Create RLS policies for fuzzing_sessions
CREATE POLICY "Users can view their own fuzzing sessions" 
  ON public.fuzzing_sessions FOR SELECT 
  USING (auth.uid() = user_id);

CREATE POLICY "Users can create their own fuzzing sessions" 
  ON public.fuzzing_sessions FOR INSERT 
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own fuzzing sessions" 
  ON public.fuzzing_sessions FOR UPDATE 
  USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own fuzzing sessions" 
  ON public.fuzzing_sessions FOR DELETE 
  USING (auth.uid() = user_id);

-- Create RLS policies for vulnerability_findings
CREATE POLICY "Users can view their own vulnerability findings" 
  ON public.vulnerability_findings FOR SELECT 
  USING (auth.uid() = user_id);

CREATE POLICY "Users can create their own vulnerability findings" 
  ON public.vulnerability_findings FOR INSERT 
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own vulnerability findings" 
  ON public.vulnerability_findings FOR UPDATE 
  USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own vulnerability findings" 
  ON public.vulnerability_findings FOR DELETE 
  USING (auth.uid() = user_id);

-- Create RLS policies for threat_reports
CREATE POLICY "Users can view their own threat reports" 
  ON public.threat_reports FOR SELECT 
  USING (auth.uid() = user_id);

CREATE POLICY "Users can create their own threat reports" 
  ON public.threat_reports FOR INSERT 
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own threat reports" 
  ON public.threat_reports FOR UPDATE 
  USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own threat reports" 
  ON public.threat_reports FOR DELETE 
  USING (auth.uid() = user_id);

-- Create indexes for better performance
CREATE INDEX idx_ml_training_results_user_id ON public.ml_training_results(user_id);
CREATE INDEX idx_ml_training_results_session_id ON public.ml_training_results(session_id);
CREATE INDEX idx_ml_payloads_user_id ON public.ml_payloads(user_id);
CREATE INDEX idx_ml_payloads_training_result_id ON public.ml_payloads(training_result_id);
CREATE INDEX idx_fuzzing_sessions_user_id ON public.fuzzing_sessions(user_id);
CREATE INDEX idx_fuzzing_sessions_session_id ON public.fuzzing_sessions(session_id);
CREATE INDEX idx_vulnerability_findings_user_id ON public.vulnerability_findings(user_id);
CREATE INDEX idx_vulnerability_findings_session_id ON public.vulnerability_findings(fuzzing_session_id);
CREATE INDEX idx_threat_reports_user_id ON public.threat_reports(user_id);
CREATE INDEX idx_threat_reports_severity ON public.threat_reports(severity);

-- Create trigger for updating timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_ml_training_results_updated_at 
    BEFORE UPDATE ON public.ml_training_results 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
