import { useState } from 'react';
import { generateReport, type ThreatResponse } from '../../api/threatApi';
import { EmailReportModal } from './EmailReportModal';

interface IncidentReportProps {
  result: ThreatResponse;
}

export function IncidentReport({ result }: IncidentReportProps) {
  const [report, setReport] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleGenerate = async () => {
    setLoading(true);
    try {
      const res = await generateReport({
        threat: result.threat,
        attack_type: result.attack_type,
        confidence: result.confidence,
        shap_values: result.shap_values || [],
        is_anomalous: result.is_anomalous || false,
        timestamp: new Date().toISOString(),
      });
      if (res.success && res.data) {
        setReport(res.data.report);
        setShowModal(true);
      }
    } catch (e) {
      console.error('Report generation failed:', e);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    if (report) {
      navigator.clipboard.writeText(report);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <>
      <button
        onClick={handleGenerate}
        disabled={loading}
        className="px-4 py-2 text-xs font-mono border border-cyan-500/50 text-cyan-400 rounded hover:bg-cyan-500/20 transition-all disabled:opacity-50 flex items-center gap-2"
      >
        {loading ? <span className="animate-spin">⟳</span> : '📄'}
        {loading ? 'GENERATING...' : 'GENERATE REPORT'}
      </button>
      {report && <EmailReportModal reportText={report} threatLevel={result.threat} />}

      {/* Modal */}
      {showModal && report && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm" onClick={() => setShowModal(false)}>
          <div className="bg-gray-900 border border-cyan-500/40 rounded-lg p-6 max-w-2xl w-full mx-4 max-h-[80vh] overflow-auto" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-cyan-400 font-mono text-sm tracking-wider">📄 INCIDENT REPORT</h3>
              <div className="flex gap-2">
                <button
                  onClick={handleCopy}
                  className="px-3 py-1 text-xs font-mono border border-cyan-500/50 text-cyan-400 rounded hover:bg-cyan-500/20 transition-all"
                >
                  {copied ? '✓ COPIED' : '📋 COPY'}
                </button>
                <button
                  onClick={() => setShowModal(false)}
                  className="px-3 py-1 text-xs font-mono border border-gray-600 text-gray-400 rounded hover:bg-gray-700/50 transition-all"
                >
                  ✕ CLOSE
                </button>
              </div>
            </div>
            <div className="font-mono text-xs text-gray-300 whitespace-pre-wrap leading-relaxed bg-black/50 border border-gray-700 rounded p-4">
              {report}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
