import { useState } from 'react';
import { ThreatInput } from '../../api/threatApi';

interface ControlPanelProps {
  onPredict: (data: ThreatInput) => void;
  loading: boolean;
  confidenceThreshold: number;
  onThresholdChange: (val: number) => void;
}

export type { ThreatInput as PredictionInput };

// Correct integer encoding to match trainer's LabelEncoder (alphabetical sort on NSL-KDD)
const PROTO_MAP: Record<string, number> = { TCP: 1, UDP: 2, ICMP: 0 };
const SVC_MAP: Record<string, number> = { HTTP: 21, FTP: 16, SMTP: 52, SSH: 54, DNS: 9, Other: 42 };
const FLAG_MAP: Record<string, number> = { 'SF (Normal)': 9, 'S0': 5, 'REJ': 1, 'RSTO': 2, 'SH': 10 };

export const PROTO_REV: Record<number, string> = { 1: 'TCP', 2: 'UDP', 0: 'ICMP' };
export const SVC_REV: Record<number, string> = { 21: 'HTTP', 16: 'FTP', 52: 'SMTP', 54: 'SSH', 9: 'DNS', 42: 'Other' };
export const FLAG_REV: Record<number, string> = { 9: 'SF', 5: 'S0', 1: 'REJ', 2: 'RSTO', 10: 'SH', 0: 'Other' };

export function ControlPanel({ onPredict, loading, confidenceThreshold, onThresholdChange }: ControlPanelProps) {
  const [protocol, setProtocol]         = useState('TCP');
  const [service, setService]           = useState('HTTP');
  const [flag, setFlag]                 = useState('SF (Normal)');
  const [duration, setDuration]         = useState(0);
  const [srcBytes, setSrcBytes]         = useState(0);
  const [dstBytes, setDstBytes]         = useState(0);
  const [failedLogins, setFailedLogins] = useState(0);
  const [loggedIn, setLoggedIn]         = useState(0);
  const [rootShell, setRootShell]       = useState(0);
  const [serrorRate, setSerrorRate]     = useState(0);
  const [count, setCount]               = useState(1);
  const [srvCount, setSrvCount]         = useState(1);
  const [dstHostCount, setDstHostCount] = useState(1);

  const handlePredict = () => {
    const sameServiceRate = count > 0 ? Math.min(srvCount / count, 1) : 1;
    const diffServiceRate = 1 - sameServiceRate;
    const currentFlag = FLAG_MAP[flag];
    // S0=5 in corrected encoding → force serror_rate high
    const effectiveSerrorRate = currentFlag === 5 ? Math.max(serrorRate, 0.9) : serrorRate;

    const input: ThreatInput = {
      duration,
      protocol_type: PROTO_MAP[protocol],
      service: SVC_MAP[service],
      flag: currentFlag,
      src_bytes: srcBytes,
      dst_bytes: dstBytes,
      land: 0, wrong_fragment: 0, urgent: 0, hot: rootShell > 0 ? 4 : 0,
      num_failed_logins: failedLogins,
      logged_in: loggedIn,
      num_compromised: failedLogins > 3 ? failedLogins : 0,
      root_shell: rootShell,
      su_attempted: rootShell > 0 ? 1 : 0,
      num_root: rootShell > 0 ? 1 : 0,
      num_file_creations: 0,
      num_shells: rootShell > 0 ? 1 : 0,
      num_access_files: 0, num_outbound_cmds: 0,
      is_host_login: 0, is_guest_login: 0,
      count, srv_count: srvCount,
      serror_rate: effectiveSerrorRate,
      srv_serror_rate: effectiveSerrorRate,
      rerror_rate: 0, srv_rerror_rate: 0,
      same_srv_rate: sameServiceRate,
      diff_srv_rate: diffServiceRate,
      srv_diff_host_rate: diffServiceRate * 0.5,
      dst_host_count: dstHostCount,
      dst_host_srv_count: Math.min(dstHostCount, srvCount),
      dst_host_same_srv_rate: sameServiceRate,
      dst_host_diff_srv_rate: diffServiceRate,
      dst_host_same_src_port_rate: sameServiceRate,
      dst_host_srv_diff_host_rate: diffServiceRate * 0.3,
      dst_host_serror_rate: effectiveSerrorRate,
      dst_host_srv_serror_rate: effectiveSerrorRate,
      dst_host_rerror_rate: 0,
      dst_host_srv_rerror_rate: 0,
    };
    onPredict(input);
  };

  const sel = 'w-full bg-gray-900 border border-cyan-500/50 text-cyan-300 rounded px-3 py-2 text-sm focus:outline-none focus:border-cyan-400 font-mono';
  const lbl = 'block text-gray-400 text-xs mb-1 font-mono tracking-wider';

  return (
    <div className="bg-black/50 border border-cyan-500/30 rounded-lg p-5 threat-panel">
      <h2 className="text-cyan-400 text-sm mb-5 font-mono tracking-widest">⚙ CONTROL PARAMETERS</h2>
      <div className="space-y-3">
        <div><label className={lbl}>PROTOCOL TYPE</label>
          <select value={protocol} onChange={e => setProtocol(e.target.value)} className={sel}>
            {Object.keys(PROTO_MAP).map(k => <option key={k}>{k}</option>)}
          </select></div>
        <div><label className={lbl}>SERVICE TYPE</label>
          <select value={service} onChange={e => setService(e.target.value)} className={sel}>
            {Object.keys(SVC_MAP).map(k => <option key={k}>{k}</option>)}
          </select></div>
        <div><label className={lbl}>CONNECTION FLAG</label>
          <select value={flag} onChange={e => setFlag(e.target.value)} className={sel}>
            {Object.keys(FLAG_MAP).map(k => <option key={k}>{k}</option>)}
          </select></div>
        <div className="grid grid-cols-2 gap-3">
          <div><label className={lbl}>DURATION: {duration}s</label>
            <input type="range" min={0} max={100} value={duration} onChange={e => setDuration(Number(e.target.value))} className="w-full accent-cyan-400" /></div>
          <div><label className={lbl}>FAILED LOGINS: {failedLogins}</label>
            <input type="range" min={0} max={10} value={failedLogins} onChange={e => setFailedLogins(Number(e.target.value))} className="w-full accent-cyan-400" /></div>
          <div><label className={lbl}>SRC BYTES</label>
            <input type="number" min={0} value={srcBytes} onChange={e => setSrcBytes(Number(e.target.value))} className={sel} /></div>
          <div><label className={lbl}>DST BYTES</label>
            <input type="number" min={0} value={dstBytes} onChange={e => setDstBytes(Number(e.target.value))} className={sel} /></div>
          <div><label className={lbl}>LOGGED IN</label>
            <select value={loggedIn} onChange={e => setLoggedIn(Number(e.target.value))} className={sel}>
              <option value={0}>NO</option><option value={1}>YES</option>
            </select></div>
          <div><label className={lbl}>ROOT SHELL</label>
            <select value={rootShell} onChange={e => setRootShell(Number(e.target.value))} className={sel}>
              <option value={0}>NO</option><option value={1}>YES</option>
            </select></div>
          <div><label className={lbl}>COUNT</label>
            <input type="number" min={0} value={count} onChange={e => setCount(Number(e.target.value))} className={sel} /></div>
          <div><label className={lbl}>SRV COUNT</label>
            <input type="number" min={0} value={srvCount} onChange={e => setSrvCount(Number(e.target.value))} className={sel} /></div>
        </div>
        <div><label className={lbl}>ERROR RATE (SYN/Flood): {serrorRate.toFixed(1)}</label>
          <input type="range" min={0} max={1} step={0.1} value={serrorRate} onChange={e => setSerrorRate(Number(e.target.value))} className="w-full accent-cyan-400" /></div>
        <div><label className={lbl}>DST HOST COUNT</label>
          <input type="number" min={0} value={dstHostCount} onChange={e => setDstHostCount(Number(e.target.value))} className={sel} /></div>

        {/* Confidence Threshold Slider */}
        <div className="mt-4 pt-4 border-t border-gray-700">
          <label className={lbl}>
            CONFIDENCE THRESHOLD: <span className="text-cyan-400">{confidenceThreshold}%</span>
          </label>
          <input
            type="range" min={30} max={99}
            value={confidenceThreshold}
            onChange={e => onThresholdChange(Number(e.target.value))}
            className="w-full accent-yellow-400"
          />
          <div className="flex justify-between text-xs font-mono text-gray-500 mt-1">
            <span>30%</span>
            <span className="text-yellow-400/70">Below threshold → ⚠ UNCERTAIN</span>
            <span>99%</span>
          </div>
        </div>

        <button onClick={handlePredict} disabled={loading}
          className="w-full bg-gradient-to-r from-cyan-600 to-cyan-800 hover:from-cyan-500 hover:to-cyan-700 text-white font-bold py-3 px-6 rounded-lg shadow-[0_0_20px_rgba(6,182,212,0.5)] hover:shadow-[0_0_30px_rgba(6,182,212,0.8)] transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed font-mono tracking-wider mt-2">
          {loading ? <span className="flex items-center justify-center gap-2"><span className="animate-spin">⚙</span> SCANNING...</span> : '▶ PREDICT THREAT'}
        </button>
        {loading && <div className="h-1 bg-gray-800 rounded-full overflow-hidden"><div className="h-full bg-cyan-400 animate-pulse w-full" /></div>}
      </div>
    </div>
  );
}
