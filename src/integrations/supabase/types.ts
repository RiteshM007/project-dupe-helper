export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instanciate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "12.2.3 (519615d)"
  }
  public: {
    Tables: {
      fuzzing_sessions: {
        Row: {
          completed_at: string | null
          configuration: Json | null
          fuzzing_type: string
          id: string
          results_summary: Json | null
          scan_duration: number | null
          session_id: string
          started_at: string | null
          status: string
          target_url: string
          tested_payloads: number | null
          total_payloads: number | null
          user_id: string
          vulnerabilities_found: number | null
        }
        Insert: {
          completed_at?: string | null
          configuration?: Json | null
          fuzzing_type?: string
          id?: string
          results_summary?: Json | null
          scan_duration?: number | null
          session_id: string
          started_at?: string | null
          status?: string
          target_url: string
          tested_payloads?: number | null
          total_payloads?: number | null
          user_id: string
          vulnerabilities_found?: number | null
        }
        Update: {
          completed_at?: string | null
          configuration?: Json | null
          fuzzing_type?: string
          id?: string
          results_summary?: Json | null
          scan_duration?: number | null
          session_id?: string
          started_at?: string | null
          status?: string
          target_url?: string
          tested_payloads?: number | null
          total_payloads?: number | null
          user_id?: string
          vulnerabilities_found?: number | null
        }
        Relationships: []
      }
      ml_payloads: {
        Row: {
          context: string | null
          created_at: string | null
          effectiveness_score: number | null
          generated_by: string | null
          id: string
          is_tested: boolean | null
          payload: string
          test_results: Json | null
          training_result_id: string | null
          user_id: string
          vulnerability_type: string | null
        }
        Insert: {
          context?: string | null
          created_at?: string | null
          effectiveness_score?: number | null
          generated_by?: string | null
          id?: string
          is_tested?: boolean | null
          payload: string
          test_results?: Json | null
          training_result_id?: string | null
          user_id: string
          vulnerability_type?: string | null
        }
        Update: {
          context?: string | null
          created_at?: string | null
          effectiveness_score?: number | null
          generated_by?: string | null
          id?: string
          is_tested?: boolean | null
          payload?: string
          test_results?: Json | null
          training_result_id?: string | null
          user_id?: string
          vulnerability_type?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "ml_payloads_training_result_id_fkey"
            columns: ["training_result_id"]
            isOneToOne: false
            referencedRelation: "ml_training_results"
            referencedColumns: ["id"]
          },
        ]
      }
      ml_training_results: {
        Row: {
          accuracy: number
          anomaly_detection_rate: number | null
          class_distribution: Json | null
          classification_report: Json | null
          confusion_matrix: Json | null
          created_at: string | null
          dataset_size: number
          f1_score: number | null
          feature_importance: Json | null
          id: string
          model_path: string | null
          model_type: string
          patterns_detected: number | null
          precision_score: number | null
          recall_score: number | null
          session_id: string
          training_duration: number | null
          updated_at: string | null
          user_id: string
        }
        Insert: {
          accuracy?: number
          anomaly_detection_rate?: number | null
          class_distribution?: Json | null
          classification_report?: Json | null
          confusion_matrix?: Json | null
          created_at?: string | null
          dataset_size?: number
          f1_score?: number | null
          feature_importance?: Json | null
          id?: string
          model_path?: string | null
          model_type?: string
          patterns_detected?: number | null
          precision_score?: number | null
          recall_score?: number | null
          session_id: string
          training_duration?: number | null
          updated_at?: string | null
          user_id: string
        }
        Update: {
          accuracy?: number
          anomaly_detection_rate?: number | null
          class_distribution?: Json | null
          classification_report?: Json | null
          confusion_matrix?: Json | null
          created_at?: string | null
          dataset_size?: number
          f1_score?: number | null
          feature_importance?: Json | null
          id?: string
          model_path?: string | null
          model_type?: string
          patterns_detected?: number | null
          precision_score?: number | null
          recall_score?: number | null
          session_id?: string
          training_duration?: number | null
          updated_at?: string | null
          user_id?: string
        }
        Relationships: []
      }
      profiles: {
        Row: {
          avatar_url: string | null
          bio: string | null
          created_at: string | null
          display_name: string | null
          id: string
          role: string | null
          updated_at: string | null
          user_id: string
        }
        Insert: {
          avatar_url?: string | null
          bio?: string | null
          created_at?: string | null
          display_name?: string | null
          id?: string
          role?: string | null
          updated_at?: string | null
          user_id: string
        }
        Update: {
          avatar_url?: string | null
          bio?: string | null
          created_at?: string | null
          display_name?: string | null
          id?: string
          role?: string | null
          updated_at?: string | null
          user_id?: string
        }
        Relationships: []
      }
      threat_reports: {
        Row: {
          created_at: string | null
          description: string | null
          detection_details: Json | null
          id: string
          resolved_at: string | null
          severity: string
          source: string
          status: string | null
          target_info: Json | null
          threat_type: string
          title: string
          user_id: string
        }
        Insert: {
          created_at?: string | null
          description?: string | null
          detection_details?: Json | null
          id?: string
          resolved_at?: string | null
          severity?: string
          source?: string
          status?: string | null
          target_info?: Json | null
          threat_type: string
          title: string
          user_id: string
        }
        Update: {
          created_at?: string | null
          description?: string | null
          detection_details?: Json | null
          id?: string
          resolved_at?: string | null
          severity?: string
          source?: string
          status?: string | null
          target_info?: Json | null
          threat_type?: string
          title?: string
          user_id?: string
        }
        Relationships: []
      }
      vulnerability_findings: {
        Row: {
          cvss_score: number | null
          discovered_at: string | null
          evidence: Json | null
          fuzzing_session_id: string
          id: string
          payload: string
          remediation_suggestion: string | null
          response_code: number | null
          response_time: number | null
          severity: string
          target_parameter: string | null
          user_id: string
          vulnerability_type: string
        }
        Insert: {
          cvss_score?: number | null
          discovered_at?: string | null
          evidence?: Json | null
          fuzzing_session_id: string
          id?: string
          payload: string
          remediation_suggestion?: string | null
          response_code?: number | null
          response_time?: number | null
          severity?: string
          target_parameter?: string | null
          user_id: string
          vulnerability_type: string
        }
        Update: {
          cvss_score?: number | null
          discovered_at?: string | null
          evidence?: Json | null
          fuzzing_session_id?: string
          id?: string
          payload?: string
          remediation_suggestion?: string | null
          response_code?: number | null
          response_time?: number | null
          severity?: string
          target_parameter?: string | null
          user_id?: string
          vulnerability_type?: string
        }
        Relationships: [
          {
            foreignKeyName: "vulnerability_findings_fuzzing_session_id_fkey"
            columns: ["fuzzing_session_id"]
            isOneToOne: false
            referencedRelation: "fuzzing_sessions"
            referencedColumns: ["id"]
          },
        ]
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      [_ in never]: never
    }
    Enums: {
      [_ in never]: never
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {},
  },
} as const
