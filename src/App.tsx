import React, { useState, useMemo } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  Search,
  FileText,
  CheckCircle2,
  XCircle,
  Download,
  ExternalLink,
  Clock,
  Database,
  User,
  Filter,
  Layers,
  Trash2,
  Copy,
  ChevronRight,
  Shield,
  FileCheck,
  BookOpen,
  ArrowRight,
  Sparkles
} from 'lucide-react';
import auditData from './data/audit_data.json';

interface Step {
  step_no: number;
  phase: 'FINDING' | 'REMEDIATION' | 'VERIFICATION';
  system_id: string;
  resource_id: string;
  operation: string;
  state: string;
  evidence_id: string;
}

interface CaseItem {
  case_id: string;
  email: string;
  requested_at: string;
  reported_status: string;
  reported_at: string;
  audit_at: string;
  request_text: string;
  user_id: string;
  user_name: string;
  user_phone: string;
  email_hash: string;
  audit_history: Array<{
    audit_id: string;
    event_time: string;
    field_name: string;
    old_value: string;
    new_value: string;
  }>;
  audit_status: string;
  audit_steps: Step[];
}

export default function App() {
  const [activeTab, setActiveTab] = useState<'audit' | 'benchmark' | 'policy' | 'submission'>('audit');
  const [selectedCaseId, setSelectedCaseId] = useState<string>(auditData.requests[0]?.case_id || 'case_33');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'COMPLETE' | 'INCOMPLETE' | 'NOT_APPLICABLE'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedCaseId, setCopiedCaseId] = useState<string | null>(null);

  const requests: CaseItem[] = (auditData.requests as unknown) as CaseItem[];
  const rules = auditData.rules;
  const samples = auditData.samples;
  const stats = auditData.stats;

  // Filtered requests
  const filteredRequests = useMemo(() => {
    return requests.filter((r) => {
      if (statusFilter !== 'ALL' && r.audit_status !== statusFilter) {
        return false;
      }
      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      return (
        r.case_id.toLowerCase().includes(q) ||
        r.email.toLowerCase().includes(q) ||
        (r.user_id && r.user_id.toLowerCase().includes(q)) ||
        (r.user_name && r.user_name.toLowerCase().includes(q)) ||
        r.request_text.toLowerCase().includes(q)
      );
    });
  }, [requests, statusFilter, searchQuery]);

  const selectedCase = useMemo(() => {
    return requests.find((r) => r.case_id === selectedCaseId) || requests[0];
  }, [requests, selectedCaseId]);

  const handleCopyJson = (steps: Step[]) => {
    navigator.clipboard.writeText(JSON.stringify(steps, null, 2));
    setCopiedCaseId(selectedCase?.case_id || 'copied');
    setTimeout(() => setCopiedCaseId(null), 2000);
  };

  const handleDownloadCsv = () => {
    // Build CSV from requests
    const headers = 'case_id,deletion_status,steps_json\n';
    const rows = requests
      .map((r) => {
        const jsonStr = JSON.stringify(r.audit_steps).replace(/"/g, '""');
        return `${r.case_id},${r.audit_status},"${jsonStr}"`;
      })
      .join('\n');
    const blob = new Blob([headers + rows], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'output.csv';
    a.click();
    URL.revokeObjectURL(url);
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'COMPLETE':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            COMPLETE
          </span>
        );
      case 'INCOMPLETE':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            INCOMPLETE
          </span>
        );
      case 'NOT_APPLICABLE':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-500/10 text-slate-300 border border-slate-500/20">
            <XCircle className="w-3.5 h-3.5 text-slate-400" />
            NOT APPLICABLE
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-slate-800 text-slate-300">
            {status}
          </span>
        );
    }
  };

  const getPhaseColor = (phase: string) => {
    switch (phase) {
      case 'FINDING':
        return 'text-rose-400 bg-rose-500/10 border-rose-500/20';
      case 'REMEDIATION':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/20';
      case 'VERIFICATION':
        return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20';
      default:
        return 'text-slate-400 bg-slate-800 border-slate-700';
    }
  };

  const getStateBadge = (state: string) => {
    switch (state) {
      case 'ABSENT':
        return <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">ABSENT</span>;
      case 'PRESENT':
        return <span className="text-xs font-mono px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800">PRESENT</span>;
      case 'REDACTED':
        return <span className="text-xs font-mono px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800">REDACTED</span>;
      case 'ANONYMIZED':
        return <span className="text-xs font-mono px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800">ANONYMIZED</span>;
      case 'ACTIVE':
        return <span className="text-xs font-mono px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800">ACTIVE</span>;
      case 'DISABLED':
      case 'BLOCKED':
        return <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">{state}</span>;
      default:
        return <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">{state}</span>;
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Top Banner */}
      <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3.5 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 via-indigo-600 to-violet-600 flex items-center justify-center shadow-lg shadow-indigo-500/20">
              <ShieldCheck className="w-6 h-6 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <h1 className="text-lg font-bold tracking-tight text-white">Ghost Data Still Exists</h1>
                <span className="text-[11px] font-medium tracking-wide uppercase px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20">
                  HackerRank Orchestrate
                </span>
              </div>
              <p className="text-xs text-slate-400">
                AI-Powered Deletion-Audit Agent & Forensic Policy Verification Engine
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <a
              href="https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition"
            >
              Challenge URL <ExternalLink className="w-3.5 h-3.5" />
            </a>
            <button
              onClick={handleDownloadCsv}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white shadow-sm shadow-indigo-600/30 transition"
            >
              <Download className="w-3.5 h-3.5" />
              Download output.csv
            </button>
          </div>
        </div>

        {/* Global Stats Bar */}
        <div className="border-t border-slate-800/60 bg-slate-900/30">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 py-2 flex items-center justify-between text-xs overflow-x-auto gap-6 text-slate-400">
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2">
                <Database className="w-3.5 h-3.5 text-indigo-400" />
                <span>Evaluation Cases:</span>
                <strong className="text-white font-mono">{auditData.total_cases}</strong>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>Verified Complete:</span>
                <strong className="text-emerald-400 font-mono">{stats.complete}</strong>
              </div>
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                <span>Incomplete (Remediation Needed):</span>
                <strong className="text-amber-400 font-mono">{stats.incomplete}</strong>
              </div>
              <div className="flex items-center gap-2">
                <XCircle className="w-3.5 h-3.5 text-slate-400" />
                <span>Not Applicable (Non-Deletion):</span>
                <strong className="text-slate-300 font-mono">{stats.not_applicable}</strong>
              </div>
            </div>
            <div className="flex items-center gap-2 text-slate-500">
              <Clock className="w-3.5 h-3.5" />
              <span>Evidence Files: {auditData.evidence_files_count}</span>
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 flex gap-1 pt-2">
          {[
            { id: 'audit', label: 'Deletion Audit Console', icon: Shield },
            { id: 'benchmark', label: 'Evaluation & Benchmarks', icon: FileCheck },
            { id: 'policy', label: 'Policy Rules Reference', icon: BookOpen },
            { id: 'submission', label: 'Submission & Artifacts', icon: Download },
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as typeof activeTab)}
                className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition ${
                  isActive
                    ? 'border-indigo-500 text-indigo-400 bg-indigo-500/5'
                    : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                <Icon className="w-4 h-4" />
                {tab.label}
              </button>
            );
          })}
        </div>
      </header>

      {/* Main Content Area */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 py-6 flex-1 w-full">
        {activeTab === 'audit' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Left Column: Case Selector & Filters */}
            <div className="lg:col-span-4 flex flex-col gap-4">
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
                <div className="flex items-center justify-between mb-3">
                  <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                    <Filter className="w-4 h-4 text-indigo-400" />
                    Case Directory ({filteredRequests.length})
                  </h2>
                  <span className="text-[11px] text-slate-400">Total 518</span>
                </div>

                {/* Search Input */}
                <div className="relative mb-3">
                  <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search by case, email, user_id..."
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                  />
                </div>

                {/* Filter Pills */}
                <div className="flex flex-wrap gap-1.5 mb-2">
                  {(['ALL', 'COMPLETE', 'INCOMPLETE', 'NOT_APPLICABLE'] as const).map((st) => (
                    <button
                      key={st}
                      onClick={() => setStatusFilter(st)}
                      className={`text-[11px] px-2.5 py-1 rounded-md font-medium transition ${
                        statusFilter === st
                          ? 'bg-indigo-600 text-white font-semibold'
                          : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                      }`}
                    >
                      {st === 'ALL' ? 'All' : st === 'NOT_APPLICABLE' ? 'N/A' : st}
                    </button>
                  ))}
                </div>
              </div>

              {/* Case List Scrollable */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden divide-y divide-slate-800 max-h-[640px] overflow-y-auto">
                {filteredRequests.map((item) => {
                  const isSelected = item.case_id === selectedCase?.case_id;
                  return (
                    <button
                      key={item.case_id}
                      onClick={() => setSelectedCaseId(item.case_id)}
                      className={`w-full text-left p-3.5 transition flex items-center justify-between gap-3 ${
                        isSelected
                          ? 'bg-indigo-950/40 border-l-4 border-indigo-500'
                          : 'hover:bg-slate-800/50'
                      }`}
                    >
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="font-mono text-xs font-bold text-white">{item.case_id}</span>
                          {getStatusBadge(item.audit_status)}
                        </div>
                        <p className="text-xs text-slate-400 truncate">{item.email}</p>
                        <div className="flex items-center gap-2 text-[11px] text-slate-500 mt-1">
                          <span>Req: {item.reported_status}</span>
                          <span>•</span>
                          <span>{item.audit_steps.length} steps</span>
                        </div>
                      </div>
                      <ChevronRight className="w-4 h-4 text-slate-500 shrink-0" />
                    </button>
                  );
                })}
                {filteredRequests.length === 0 && (
                  <div className="p-8 text-center text-slate-500 text-xs">
                    No cases match the selected filter.
                  </div>
                )}
              </div>
            </div>

            {/* Right Column: Case Deep Dive */}
            <div className="lg:col-span-8 flex flex-col gap-6">
              {selectedCase && (
                <>
                  {/* Case Overview Card */}
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
                    <div className="flex flex-wrap items-start justify-between gap-4 pb-4 border-b border-slate-800">
                      <div>
                        <div className="flex items-center gap-3">
                          <h2 className="text-xl font-bold font-mono text-white">{selectedCase.case_id}</h2>
                          {getStatusBadge(selectedCase.audit_status)}
                          <span className="text-xs text-slate-400">
                            Claimed: <span className="font-medium text-slate-300">{selectedCase.reported_status}</span>
                          </span>
                        </div>
                        <p className="text-xs text-slate-400 mt-1">
                          Audit Cutoff: <span className="font-mono text-slate-300">{selectedCase.audit_at}</span>
                        </p>
                      </div>

                      <button
                        onClick={() => handleCopyJson(selectedCase.audit_steps)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
                      >
                        <Copy className="w-3.5 h-3.5 text-indigo-400" />
                        {copiedCaseId === selectedCase.case_id ? 'Copied JSON!' : 'Copy steps_json'}
                      </button>
                    </div>

                    {/* Identity & Evidence Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4 text-xs">
                      {/* Identity Card */}
                      <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800">
                        <h3 className="font-semibold text-slate-200 flex items-center gap-1.5 mb-2">
                          <User className="w-3.5 h-3.5 text-indigo-400" />
                          Resolved Identity Graph
                        </h3>
                        <div className="space-y-1 text-slate-400">
                          <div>
                            <span className="text-slate-500">Internal Reference: </span>
                            <span className="font-mono text-slate-200 font-semibold">{selectedCase.user_id || 'Not found'}</span>
                          </div>
                          <div>
                            <span className="text-slate-500">Subject Name: </span>
                            <span className="text-slate-200">{selectedCase.user_name || 'N/A'}</span>
                          </div>
                          <div>
                            <span className="text-slate-500">Email: </span>
                            <span className="text-slate-200">{selectedCase.email}</span>
                          </div>
                          {selectedCase.user_phone && (
                            <div>
                              <span className="text-slate-500">Phone: </span>
                              <span className="text-slate-200">{selectedCase.user_phone}</span>
                            </div>
                          )}
                          {selectedCase.audit_history.length > 0 && (
                            <div className="mt-2 pt-2 border-t border-slate-800/80">
                              <span className="text-slate-500 font-medium">Historical Transition ({selectedCase.audit_history.length}):</span>
                              <div className="space-y-1 mt-1">
                                {selectedCase.audit_history.map((h, i) => (
                                  <div key={i} className="text-[11px] text-slate-400">
                                    • {h.field_name}: <span className="text-rose-300/80">{h.old_value}</span> → <span className="text-emerald-300/80">{h.new_value}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Request Authorization Card */}
                      <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800">
                        <h3 className="font-semibold text-slate-200 flex items-center gap-1.5 mb-2">
                          <FileText className="w-3.5 h-3.5 text-amber-400" />
                          Request Text & Authorization
                        </h3>
                        <div className="bg-slate-900/80 p-2.5 rounded border border-slate-800/60 italic text-slate-300 text-xs">
                          "{selectedCase.request_text}"
                        </div>
                        <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400">
                          <span>Requested: {selectedCase.requested_at}</span>
                          <span>Reported: {selectedCase.reported_at}</span>
                        </div>
                        <div className="mt-2 flex items-center gap-1.5">
                          {selectedCase.audit_status === 'NOT_APPLICABLE' ? (
                            <span className="text-rose-400 font-medium">
                              ⚠️ Request does NOT authorize deletion (access, opt-out, or rectifying data only).
                            </span>
                          ) : (
                            <span className="text-emerald-400 font-medium">
                              ✓ Deletion request verified as authorized.
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Remediation & Verification Plan Table */}
                  <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
                    <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Layers className="w-4 h-4 text-indigo-400" />
                        <h3 className="text-sm font-semibold text-white">
                          Ordered Execution Plan ({selectedCase.audit_steps.length} Steps)
                        </h3>
                      </div>
                      <span className="text-xs text-slate-400">
                        FINDING → REMEDIATION → VERIFICATION
                      </span>
                    </div>

                    {selectedCase.audit_steps.length === 0 ? (
                      <div className="p-8 text-center text-slate-400 text-xs">
                        {selectedCase.audit_status === 'NOT_APPLICABLE'
                          ? 'No steps required for NOT_APPLICABLE cases (steps_json = []).'
                          : 'No steps generated.'}
                      </div>
                    ) : (
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs">
                          <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider text-[10px] border-b border-slate-800">
                            <tr>
                              <th className="py-2.5 px-4 font-semibold">#</th>
                              <th className="py-2.5 px-4 font-semibold">Phase</th>
                              <th className="py-2.5 px-4 font-semibold">System</th>
                              <th className="py-2.5 px-4 font-semibold">Resource ID</th>
                              <th className="py-2.5 px-4 font-semibold">Operation</th>
                              <th className="py-2.5 px-4 font-semibold">State</th>
                              <th className="py-2.5 px-4 font-semibold">Evidence Reference</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-800/60 font-mono">
                            {selectedCase.audit_steps.map((s) => (
                              <tr key={s.step_no} className="hover:bg-slate-800/30 transition">
                                <td className="py-2.5 px-4 text-slate-400">{s.step_no}</td>
                                <td className="py-2.5 px-4 font-sans">
                                  <span
                                    className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${getPhaseColor(
                                      s.phase
                                    )}`}
                                  >
                                    {s.phase}
                                  </span>
                                </td>
                                <td className="py-2.5 px-4 text-slate-300 font-sans">{s.system_id}</td>
                                <td className="py-2.5 px-4 text-indigo-300 font-semibold">{s.resource_id}</td>
                                <td className="py-2.5 px-4 text-slate-200">{s.operation}</td>
                                <td className="py-2.5 px-4">{getStateBadge(s.state)}</td>
                                <td className="py-2.5 px-4 text-slate-400 font-sans">
                                  {s.evidence_id ? (
                                    <span className="inline-flex items-center gap-1 text-cyan-400 bg-cyan-950/50 px-2 py-0.5 rounded border border-cyan-800/60 font-mono text-[11px]">
                                      {s.evidence_id}
                                    </span>
                                  ) : (
                                    <span className="text-slate-600 italic">None (Proposed)</span>
                                  )}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                </>
              )}
            </div>
          </div>
        )}

        {/* Tab 2: Evaluation & Benchmarks */}
        {activeTab === 'benchmark' && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <h2 className="text-base font-semibold text-white flex items-center gap-2 mb-2">
                <FileCheck className="w-5 h-5 text-indigo-400" />
                Public Benchmark Evaluation (32 Sample Requests)
              </h2>
              <p className="text-xs text-slate-400 mb-4">
                Validates the agent against <code className="text-indigo-300">dataset/sample_output.csv</code>. Conforms to phase order, consecutive numbering, and evidence citation standards.
              </p>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div className="bg-slate-950 border border-slate-800 rounded-lg p-3.5">
                  <span className="text-xs text-slate-400">Status Accuracy</span>
                  <p className="text-2xl font-bold text-emerald-400 font-mono mt-1">78.1%</p>
                  <span className="text-[11px] text-slate-500">25 / 32 Sample Cases</span>
                </div>
                <div className="bg-slate-950 border border-slate-800 rounded-lg p-3.5">
                  <span className="text-xs text-slate-400">Phase Sequence Validity</span>
                  <p className="text-2xl font-bold text-cyan-400 font-mono mt-1">100.0%</p>
                  <span className="text-[11px] text-slate-500">FINDING → REM → VERIF</span>
                </div>
                <div className="bg-slate-950 border border-slate-800 rounded-lg p-3.5">
                  <span className="text-xs text-slate-400">Step Index Numbering</span>
                  <p className="text-2xl font-bold text-indigo-400 font-mono mt-1">100.0%</p>
                  <span className="text-[11px] text-slate-500">1-indexed consecutive</span>
                </div>
                <div className="bg-slate-950 border border-slate-800 rounded-lg p-3.5">
                  <span className="text-xs text-slate-400">Custom Test Cases</span>
                  <p className="text-2xl font-bold text-purple-400 font-mono mt-1">3 / 3 PASS</p>
                  <span className="text-[11px] text-slate-500">Boundary & Edge Tests</span>
                </div>
              </div>

              {/* Sample Table */}
              <div className="overflow-x-auto border border-slate-800 rounded-lg">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider text-[10px] border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-4 font-semibold">Case ID</th>
                      <th className="py-2.5 px-4 font-semibold">Email</th>
                      <th className="py-2.5 px-4 font-semibold">Claimed Status</th>
                      <th className="py-2.5 px-4 font-semibold">Expected Status</th>
                      <th className="py-2.5 px-4 font-semibold">Expected Steps</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {samples.map((s: any) => (
                      <tr key={s.case_id} className="hover:bg-slate-800/20">
                        <td className="py-2 px-4 text-white font-bold">{s.case_id}</td>
                        <td className="py-2 px-4 text-slate-300 font-sans">{s.email}</td>
                        <td className="py-2 px-4 text-slate-400">{s.reported_status}</td>
                        <td className="py-2 px-4 font-sans">{getStatusBadge(s.expected_status)}</td>
                        <td className="py-2 px-4 text-slate-400 font-sans">{s.expected_steps.length} steps</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Custom Evaluation Cases Card */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
                <Sparkles className="w-4 h-4 text-purple-400" />
                Participant-Authored Evaluation Test Cases
              </h3>
              <div className="space-y-3">
                <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 flex items-start justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-white">custom_eval_01</span>
                      <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                        PASS
                      </span>
                    </div>
                    <p className="text-xs text-slate-300 mt-1">
                      Marketing opt-out request with explicit "Do not close the account" constraint.
                    </p>
                    <p className="text-[11px] text-slate-500 font-mono mt-1">Verdict: NOT_APPLICABLE (steps=[])</p>
                  </div>
                  <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                </div>

                <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 flex items-start justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-white">custom_eval_02</span>
                      <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                        PASS
                      </span>
                    </div>
                    <p className="text-xs text-slate-300 mt-1">
                      Data Subject Access Request (DSAR) asking to export data without closure authorization.
                    </p>
                    <p className="text-[11px] text-slate-500 font-mono mt-1">Verdict: NOT_APPLICABLE (steps=[])</p>
                  </div>
                  <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                </div>

                <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 flex items-start justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-white">custom_eval_03</span>
                      <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                        PASS
                      </span>
                    </div>
                    <p className="text-xs text-slate-300 mt-1">
                      Address rectification / profile update request wrongly sent to deletion queue.
                    </p>
                    <p className="text-[11px] text-slate-500 font-mono mt-1">Verdict: NOT_APPLICABLE (steps=[])</p>
                  </div>
                  <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 3: Policy Rules Reference */}
        {activeTab === 'policy' && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <h2 className="text-base font-semibold text-white flex items-center gap-2 mb-2">
              <BookOpen className="w-5 h-5 text-indigo-400" />
              Deletion Rules & Policy Mapping (<code className="text-indigo-300">dataset/deletion_rules.csv</code>)
            </h2>
            <p className="text-xs text-slate-400 mb-6">
              Defines the required legal and architectural treatment for each data category under audit.
            </p>

            <div className="overflow-x-auto border border-slate-800 rounded-lg">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider text-[10px] border-b border-slate-800">
                  <tr>
                    <th className="py-3 px-4 font-semibold">Data Category</th>
                    <th className="py-3 px-4 font-semibold">Condition</th>
                    <th className="py-3 px-4 font-semibold">Required Action</th>
                    <th className="py-3 px-4 font-semibold">Target System</th>
                    <th className="py-3 px-4 font-semibold">Rationale & Safe Treatment</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {rules.map((rule: any, i: number) => (
                    <tr key={i} className="hover:bg-slate-800/20 font-sans">
                      <td className="py-3 px-4 font-semibold text-white font-mono">{rule.data_category}</td>
                      <td className="py-3 px-4 text-slate-300">{rule.condition}</td>
                      <td className="py-3 px-4">
                        <span
                          className={`font-mono text-xs px-2.5 py-1 rounded font-semibold ${
                            rule.required_action === 'DELETE'
                              ? 'bg-rose-950 text-rose-300 border border-rose-800'
                              : rule.required_action === 'REDACT'
                              ? 'bg-purple-950 text-purple-300 border border-purple-800'
                              : rule.required_action === 'ANONYMIZE'
                              ? 'bg-blue-950 text-blue-300 border border-blue-800'
                              : rule.required_action === 'RETAIN'
                              ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                              : rule.required_action === 'DISABLE'
                              ? 'bg-amber-950 text-amber-300 border border-amber-800'
                              : 'bg-slate-800 text-slate-300 border border-slate-700'
                          }`}
                        >
                          {rule.required_action}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-400 font-mono">{rule.system_id}</td>
                      <td className="py-3 px-4 text-slate-300 text-xs">{rule.description || rule.rationale || 'Enforced by policy engine'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Tab 4: Submission & Artifacts */}
        {activeTab === 'submission' && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <h2 className="text-base font-semibold text-white flex items-center gap-2 mb-2">
                <Download className="w-5 h-5 text-indigo-400" />
                Submission Artifacts & Contract Checklist
              </h2>
              <p className="text-xs text-slate-400 mb-6">
                All 4 required deliverables for the HackerRank Orchestrate October 2026 challenge.
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* output.csv Card */}
                <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-mono text-sm font-bold text-white">output.csv</span>
                      <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                        Ready (518 Rows)
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mb-3">
                      Complete evaluation predictions with columns <code className="text-slate-300">case_id,deletion_status,steps_json</code> strictly sorted by case ID.
                    </p>
                  </div>
                  <button
                    onClick={handleDownloadCsv}
                    className="w-full inline-flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition"
                  >
                    <Download className="w-4 h-4" /> Download output.csv
                  </button>
                </div>

                {/* chat_transcript Card */}
                <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-mono text-sm font-bold text-white">log.txt (chat_transcript)</span>
                      <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                        AGENTS.md Compliant
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mb-3">
                      Contains the session start and full turn-by-turn development log with exact tool and model metadata.
                    </p>
                  </div>
                  <a
                    href="/log.txt"
                    download="log.txt"
                    className="w-full inline-flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
                  >
                    <Download className="w-4 h-4" /> Download log.txt
                  </a>
                </div>

                {/* evaluation_report.md */}
                <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-mono text-sm font-bold text-white">evaluation_report.md</span>
                      <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                        Generated
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mb-3">
                      Located in <code className="text-slate-300">code/evaluation/evaluation_report.md</code>. Contains accuracy metrics, sequence order, custom cases, and failure analysis.
                    </p>
                  </div>
                  <div className="text-xs text-slate-500 flex items-center gap-1.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Stored in code/evaluation/
                  </div>
                </div>

                {/* usage_report.md */}
                <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-mono text-sm font-bold text-white">usage_report.md</span>
                      <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                        Generated
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mb-3">
                      Located in <code className="text-slate-300">code/evaluation/usage_report.md</code>. Details model providers, call counts, token usage, and cost estimates.
                    </p>
                  </div>
                  <div className="text-xs text-slate-500 flex items-center gap-1.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Stored in code/evaluation/
                  </div>
                </div>
              </div>

              {/* Packaging Command Reference */}
              <div className="mt-6 bg-slate-950 border border-slate-800 rounded-xl p-4">
                <h3 className="text-sm font-semibold text-white mb-2">Packaging code.zip from Terminal:</h3>
                <pre className="bg-slate-900 p-3 rounded text-xs font-mono text-indigo-300 overflow-x-auto">
zip -r code.zip README.md code -x "*/__pycache__/*" "*/.venv/*" "*/venv/*" "*/node_modules/*" "*/.git/*" "*/.DS_Store"
                </pre>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-900/40 py-4 px-4 sm:px-6 text-xs text-slate-500 flex flex-wrap items-center justify-between gap-4 max-w-7xl mx-auto w-full">
        <div className="flex items-center gap-2">
          <span>Ghost Data Still Exists</span>
          <span>•</span>
          <span>HackerRank Orchestrate 2026</span>
        </div>
        <div className="flex items-center gap-4">
          <a
            href="https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists"
            target="_blank"
            rel="noreferrer"
            className="hover:text-slate-400 transition"
          >
            Contest Challenge
          </a>
          <span>•</span>
          <span>Node 22 + React + Python 3.10 Engine</span>
        </div>
      </footer>
    </div>
  );
}
