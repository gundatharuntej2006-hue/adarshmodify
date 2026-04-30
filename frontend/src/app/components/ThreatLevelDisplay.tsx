import { ThreatResponse, AttackType } from '../../api/threatApi';
import { ZeroDayBadge } from './ZeroDayBadge';
import { IncidentReport } from './IncidentReport';

interface ThreatLevelDisplayProps {
  level: 'LOW' | 'MEDIUM' | 'HIGH';
  result: ThreatResponse | null;
  confidenceThreshold: number;
  submittedInput?: Record<string, any> | null;
}

const ATTACK_COLORS: Record<string, string> = {
  Normal: 'text-green-400',
  DoS:    'text-red-400',
  Probe:  'text-yellow-400',
  R2L:    'text-orange-400',
  U2R:    'text-purple-400',
};

const ATTACK_BG: Record<string, string> = {
  Normal: 'bg-green-500/20 border-green-500/40',
  DoS:    'bg-red-500/20 border-red-500/40',
  Probe:  'bg-yellow-500/20 border-yellow-500/40',
  R2L:    'bg-orange-500/20 border-orange-500/40',
  U2R:    'bg-purple-500/20 border-purple-500/40',
};

const ATTACK_BAR_COLOR: Record<string, string> = {
  Normal: 'bg-green-500',
  DoS:    'bg-red-500',
  Probe:  'bg-yellow-500',
  R2L:    'bg-orange-500',
  U2R:    'bg-purple-500',
};

const ATTACK_DESCRIPTIONS: Record<string, string> = {
  Normal: 'No malicious activity detected',
  DoS:    'Denial of Service — flooding the target',
  Probe:  'Surveillance/scanning — probing for vulnerabilities',
  R2L:    'Remote to Local — unauthorized remote access attempt',
  U2R:    'User to Root — privilege escalation attempt',
};

const ATTACK_ICONS: Record<string, string> = {
  Normal: '✓',
  DoS:    '⚡',
  Probe:  '⬡',
  R2L:    '🔑',
  U2R:    '☠',
};

// Reverse maps for displaying input summary
const PROTO_LABELS: Record<number, string> = { 0: 'ICMP', 1: 'TCP', 2: 'UDP' };
const FLAG_LABELS: Record<number, string> = { 0: 'OTH', 1: 'REJ', 2: 'RSTO', 5: 'S0', 9: 'SF', 10: 'SH' };

export function ThreatLevelDisplay({ level, result, confidenceThreshold, submittedInput }: ThreatLevelDisplayProps) {
  const cfg = {
    LOW:    { border: 'border-green-500',  glow: 'shadow-[0_0_20px_rgba(34,197,94,0.5)]',   text: 'text-green-400',  bg: 'bg-green-500/10',  label: 'ALL CLEAR', icon: '✓' },
    MEDIUM: { border: 'border-yellow-500', glow: 'shadow-[0_0_20px_rgba(234,179,8,0.5)]',   text: 'text-yellow-400', bg: 'bg-yellow-500/10', label: 'MONITOR CLOSELY', icon: '◈' },
    HIGH:   { border: 'border-red-500 animate-pulse', glow: 'shadow-[0_0_30px_rgba(239,68,68,0.8)] animate-pulse', text: 'text-red-400 animate-pulse', bg: 'bg-red-500/20', label: 'THREAT DETECTED', icon: '⚠' },
  }[level];

  const attackType = result?.attack_type ?? null;
  const attackProbs = result?.attack_probabilities ?? null;
  const isUncertain = result ? result.confidence < confidenceThreshold : false;

  return (
    <div className={`relative border-4 ${cfg.border} ${cfg.glow} ${cfg.bg} rounded-lg p-8 w-full threat-panel`}>
      {level === 'HIGH' && (
        <div className="absolute -top-4 -right-4 flex items-center gap-2 bg-red-600 px-4 py-2 rounded-lg animate-pulse">
          <span className="text-xl">🚨</span>
          <span className="font-bold text-white font-mono text-sm">ALERT</span>
        </div>
      )}
      <div className="text-center">
        <div className="text-xs tracking-widest text-gray-400 mb-2 font-mono">THREAT LEVEL</div>
        <div className={`text-6xl font-bold tracking-wider ${cfg.text} font-mono`}>{level}</div>
        <div className={`text-sm mt-2 font-mono tracking-widest ${cfg.text} opacity-70`}>{cfg.label}</div>

        {/* Uncertain badge */}
        {isUncertain && (
          <div className="mt-3 inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-yellow-500/60 bg-yellow-500/15 animate-pulse">
            <span className="text-yellow-400 font-mono font-bold text-sm tracking-wider">
              ⚠ UNCERTAIN — NEEDS HUMAN REVIEW
            </span>
          </div>
        )}

        {/* Attack Type Badge */}
        {attackType && !isUncertain && (
          <div className="mt-4 space-y-3">
            <div className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg border ${ATTACK_BG[attackType] || 'bg-gray-500/20 border-gray-500/40'}`}>
              <span className={`text-lg font-bold font-mono tracking-wider ${ATTACK_COLORS[attackType] || 'text-gray-400'}`}>
                {ATTACK_ICONS[attackType] || '?'} {attackType === 'Normal' ? 'NORMAL TRAFFIC' : `${attackType.toUpperCase()} ATTACK DETECTED`}
              </span>
            </div>
            <div className="text-xs text-gray-500 font-mono">
              {ATTACK_DESCRIPTIONS[attackType] || ''}
            </div>
          </div>
        )}

        {/* Zero-Day Badge — only when anomaly is real AND not clearly normal */}
        {result && !(result.attack_type === 'Normal' && result.confidence > 75) && (
          <ZeroDayBadge
            isAnomalous={result.is_anomalous ?? false}
            attackType={result.attack_type ?? 'Normal'}
            anomalyScore={result.anomaly_score}
          />
        )}

        {/* Attack Category Probabilities */}
        {attackProbs && (
          <div className="mt-4 text-left space-y-1.5">
            <div className="text-xs text-gray-500 font-mono tracking-wider mb-2 text-center">ATTACK CATEGORY ANALYSIS</div>
            {(['Normal', 'DoS', 'Probe', 'R2L', 'U2R'] as AttackType[]).map((cat) => {
              const val = attackProbs[cat] ?? 0;
              return (
                <div key={cat} className="flex items-center gap-2">
                  <span className={`text-xs font-mono w-14 text-right ${ATTACK_COLORS[cat]}`}>{cat}</span>
                  <div className="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-1000 ${ATTACK_BAR_COLOR[cat]}`}
                      style={{ width: `${val}%` }}
                    />
                  </div>
                  <span className="text-xs font-mono text-gray-400 w-12">{val.toFixed(1)}%</span>
                  {/* Flag dangerous runners-up */}
                  {['U2R', 'R2L'].includes(cat) && val > 10 && cat !== attackType && (
                    <span className="text-[9px] font-mono text-yellow-400 ml-1">⚠ ELEVATED</span>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* Confidence bar */}
        {result && (
          <div className="mt-4">
            <div className="text-xs text-gray-500 mb-1 font-mono">CONFIDENCE: {result.confidence.toFixed(1)}%</div>
            <div className="h-2 bg-gray-800 rounded-full overflow-hidden relative">
              <div
                className={`h-full rounded-full transition-all duration-1000 ${level === 'HIGH' ? 'bg-red-500' : level === 'MEDIUM' ? 'bg-yellow-500' : 'bg-green-500'}`}
                style={{ width: `${result.confidence}%` }}
              />
              {/* Threshold marker */}
              <div
                className="absolute top-0 h-full w-0.5 bg-yellow-400/70"
                style={{ left: `${confidenceThreshold}%` }}
                title={`Threshold: ${confidenceThreshold}%`}
              />
            </div>
          </div>
        )}

        {/* Level indicators */}
        <div className="mt-4 flex justify-center gap-2">
          <div className={`w-16 h-2 rounded-full ${level === 'LOW' ? 'bg-green-500' : 'bg-gray-700'}`} />
          <div className={`w-16 h-2 rounded-full ${level === 'MEDIUM' ? 'bg-yellow-500' : 'bg-gray-700'}`} />
          <div className={`w-16 h-2 rounded-full ${level === 'HIGH' ? 'bg-red-500 animate-pulse' : 'bg-gray-700'}`} />
        </div>

        {/* Analyzed Parameters Summary */}
        {result && submittedInput && (
          <div className="mt-4 rounded-lg p-3 text-left" style={{ background: 'rgba(255,255,255,0.03)' }}>
            <div className="text-[10px] text-gray-500 font-mono tracking-widest mb-2">ANALYZED PARAMETERS</div>
            <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[10px] font-mono text-gray-500">
              <span>Protocol: <b className="text-white">{PROTO_LABELS[submittedInput.protocol_type as number] ?? '?'}</b></span>
              <span>Flag: <b className="text-white">{FLAG_LABELS[submittedInput.flag as number] ?? '?'}</b></span>
              <span>SRC Bytes: <b className="text-white">{Number(submittedInput.src_bytes ?? 0).toLocaleString()}</b></span>
              <span>DST Bytes: <b className="text-white">{Number(submittedInput.dst_bytes ?? 0).toLocaleString()}</b></span>
              <span>Failed Logins: <b style={{ color: Number(submittedInput.num_failed_logins ?? 0) >= 5 ? '#E24B4A' : '#fff' }}>
                {submittedInput.num_failed_logins ?? 0}
              </b></span>
              <span>Root Shell: <b style={{ color: Number(submittedInput.root_shell ?? 0) >= 1 ? '#FF0055' : '#fff' }}>
                {Number(submittedInput.root_shell ?? 0) >= 1 ? 'YES' : 'NO'}
              </b></span>
              <span>Count: <b className="text-white">{submittedInput.count ?? 0}</b></span>
              <span>Error Rate: <b className="text-white">{Number(submittedInput.serror_rate ?? 0).toFixed(1)}</b></span>
            </div>
          </div>
        )}

        {/* Generate Report button */}
        {result && (
          <div className="mt-4 flex justify-center">
            <IncidentReport result={result} />
          </div>
        )}
      </div>
    </div>
  );
}
