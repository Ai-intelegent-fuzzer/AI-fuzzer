export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
export type Confidence = 'High' | 'Medium' | 'Low';
export type DetectionResult = 'PASS' | 'FAIL' | 'INCONCLUSIVE';
export type ScanStatus = 'Completed' | 'Running' | 'Failed' | 'Queued' | 'Cancelled';
export type TargetType = 'LLM API' | 'AI Chatbot' | 'RAG Application' | 'AI Agent';
export type TargetStatus = 'Operational' | 'Warning' | 'Offline';
export type AuthenticationType = 'None' | 'API Key' | 'Bearer Token';
export type ScanProfile = 'Quick' | 'Standard' | 'Comprehensive';
export type VulnerabilityCategory = 'Prompt Injection' | 'Jailbreak' | 'Context Poisoning' | 'Data Leakage';

export interface Target {
  targetId: string;
  name: string;
  type: TargetType;
  status: TargetStatus;
  endpoint: string;
  lastTested: string;
  riskProfile: 'Low' | 'Medium' | 'High';
  authType?: AuthenticationType;
  modelName?: string;
  description?: string;
  lastScan?: string;
  createdAt?: string;
}

export interface EvidenceStep {
  label: string;
  value: string;
}

export interface Scan {
  scanId: string;
  target: string;
  targetId?: string;
  name?: string;
  status: ScanStatus;
  testsTotal: number;
  testsCompleted: number;
  findingsCount: number;
  startedAt: string;
  duration: string;
  endedAt?: string;
  categories?: VulnerabilityCategory[];
  profile?: ScanProfile;
  timeout?: number;
  delayMs?: number;
  currentStage?: string;
  progress?: number;
  currentCategory?: string;
  elapsedSeconds?: number;
}

export interface Finding {
  findingId: string;
  vulnerabilityType: string;
  severity: Severity;
  confidence: Confidence;
  targetId: string;
  targetName: string;
  testId: string;
  evidence: string;
  expectedBehavior: string;
  actualBehavior: string;
  timestamp: string;
  recommendation: string;
  detectionResult: DetectionResult;
  status?: 'Open' | 'Investigating' | 'Resolved';
  evidenceSequence?: EvidenceStep[];
}

export interface Report {
  reportId: string;
  title: string;
  generatedAt: string;
  format: 'JSON' | 'PDF';
  status: 'Ready' | 'Generating' | 'Archived';
  findingsCount: number;
  summary: string;
  scanId?: string;
  targetId?: string;
  targetName?: string;
  highestSeverity?: Severity;
  executiveSummary?: string;
  targetInformation?: string;
  scanConfiguration?: string;
  testsExecuted?: number;
  severityDistribution?: Array<{ name: string; value: number }>;
  detailedFindings?: Array<{ id: string; type: string; severity: Severity; description: string; evidence: string; recommendation: string; }>;
  evidenceReferences?: string[];
  recommendedRemediation?: string[];
}

export interface SystemHealthState {
  scannerEngine: string;
  responseAnalyzer: string;
  evidenceStore: string;
  activeScans: number;
}

export interface DashboardSummary {
  totalScans: number;
  testsExecuted: number;
  vulnerabilitiesFound: number;
  criticalHighFindings: number;
}

export interface TargetDraft {
  name: string;
  type: TargetType;
  endpoint: string;
  authType: AuthenticationType;
  modelName: string;
  description: string;
}

export interface ConnectionTestResult {
  status: 'Testing...' | 'Connection Successful' | 'Connection Failed';
  message: string;
}

export interface ScanStartInput {
  targetId: string;
  name: string;
  categories: VulnerabilityCategory[];
  profile: ScanProfile;
  timeout: number;
  delayMs: number;
}
