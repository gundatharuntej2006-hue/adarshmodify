import { useState, useCallback, useRef, useEffect } from 'react';
import { MatrixRain } from './components/MatrixRain';
import { RadarSweep } from './components/RadarSweep';
import { TerminalLog } from './components/TerminalLog';
import { ThreatLevelDisplay } from './components/ThreatLevelDisplay';
import { AnalyticsPanel } from './components/AnalyticsPanel';
import { ModelComparison } from './components/ModelComparison';
import { ControlPanel, PROTO_REV, SVC_REV, FLAG_REV } from './components/ControlPanel';
import { PredictionHistory } from './components/PredictionHistory';
import { BatchAnalysis } from './components/BatchAnalysis';
import { AttackHeatmap } from './components/AttackHeatmap';
import { AttackWorldMap } from './components/AttackWorldMap';
import { NetworkGraph } from './components/NetworkGraph';
import { predictThreat } from '../api/threatApi';
import { SimulationRunner } from './components/SimulationRunner';
import { DriftWarning } from './components/DriftWarning';
import { SocModeButton, SocModeWrapper } from './components/SocMode';
import { ThreatInput, ThreatResponse, PredictionHistoryEntry, getApiStatus, ApiStatus } from '../api/threatApi';
import { UbaDashboard } from './components/UbaDashboard';
import { AriaChatbot } from './components/AriaChatbot';
import { useThreatPredict } from '../hooks/useThreatPredict';
import { useAudioAlert } from '../hooks/useAudioAlert';
import { useThreatLevel } from './context/ThreatLevelContext';
import { LiveThreatFeed } from './components/LiveThreatFeed';
import { toast } from 'sonner';

type ThreatLevel = 'LOW' | 'MEDIUM' | 'HIGH';
type TabMode = 'single' | 'batch' | 'uba';

export default function App() {
  const [threatLevel, setThreatLevel] = useState<ThreatLevel>('LOW');
  const [threatProbability, setThreatProbability] = useState(15);
  const [activeTab, setActiveTab] = useState<TabMode>('single');
  const [socMode, setSocMode] = useState(false);
  const [history, setHistory] = useState<PredictionHistoryEntry[]>([]);
  const { result, loading, error, predict } = useThreatPredict();
  const [apiStatus, setApiStatus] = useState<ApiStatus | null>(null);

  const ctx = useThreatLevel();

  // Fetch API status on mount and every 30 seconds
  useEffect(() => {
    const fetchStatus = () => {
      getApiStatus().then(setApiStatus).catch(() => setApiStatus(null));
    };
    fetchStatus();
    const interval = setInterval(fetchStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  // Audio alerts
  useAudioAlert(threatLevel);

  const addToHistory = useCallback((res: ThreatResponse, input: ThreatInput) => {
    const entry: PredictionHistoryEntry = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      timestamp: new Date().toLocaleTimeString(),
      protocol: PROTO_REV[input.protocol_type] || 'TCP',
      service: SVC_REV[input.service] || 'Other',
      flag: FLAG_REV[input.flag] || 'SF',
      threatLevel: res.threat,
      attackType: res.attack_type || 'Unknown',
      confidence: res.confidence,
      isAnomalous: res.is_anomalous || false,
      shapValues: res.shap_values,
      input,
    };
    setHistory(prev => [...prev, entry].slice(-100));
  }, []);




  // Sync state from API result
  if (result && result.threat !== threatLevel) {
    setThreatLevel(result.threat);
    setThreatProbability(result.confidence);
    ctx.setThreatLevel(result.threat);
    ctx.setAttackType(result.attack_type ?? null);
    ctx.setIsZeroDay(
      (result.is_anomalous ?? false) && result.attack_type === 'Normal'
    );
  }

  const handleSimulationPrediction = useCallback((res: ThreatResponse, input: ThreatInput) => {
    setThreatLevel(res.threat);
    setThreatProbability(res.confidence);
    ctx.setThreatLevel(res.threat);
    ctx.setAttackType(res.attack_type ?? null);
    ctx.setIsZeroDay((res.is_anomalous ?? false) && res.attack_type === 'Normal');
    addToHistory(res, input);
  }, [ctx, addToHistory]);

  // Predict that also records history
  const lastInputRef = useRef<ThreatInput | null>(null);
  const predictAndRecord = async (data: ThreatInput) => {
    lastInputRef.current = data;
    try {
      const res = await predictThreat(data);
      setThreatLevel(res.threat);
      setThreatProbability(res.confidence);
      ctx.setThreatLevel(res.threat);
      ctx.setAttackType(res.attack_type ?? null);
      ctx.setIsZeroDay((res.is_anomalous ?? false) && res.attack_type === 'Normal');
      addToHistory(res, data);
      
      toast.info('Simulating attack pattern...', { duration: 4000 });
      setTimeout(() => {
        toast.success('Simulation complete');
      }, 5000);

      await predict(data);
    } catch (e) {
      await predict(data);
    }
  };

  const tabBtn = (tab: TabMode, label: string) => (
    <button
      onClick={() => setActiveTab(tab)}
      className={`px-4 py-2 text-xs font-mono tracking-wider transition-all border-b-2 ${
        activeTab === tab
          ? 'text-cyan-400 border-cyan-400'
          : 'text-gray-500 border-transparent hover:text-gray-300'
      }`}
    >
      {label}
    </button>
  );

  const dashboard = (
    <div className={`min-h-screen bg-gradient-to-br from-black via-gray-900 to-black text-white overflow-auto threat-bg-glow`}>
      <MatrixRain />

      <div className="relative z-10 p-4 lg:p-6">
        {/* Model Drift Warning */}
        <DriftWarning />

        {/* Header */}
        <header className="border-b-2 border-cyan-500/50 pb-4 mb-6">
          <div className="flex flex-col lg:flex-row items-center justify-between gap-4">
            <div>
              <h1 className="text-3xl lg:text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-green-400 tracking-wider font-mono">
                AI THREAT RISK PREDICTION SYSTEM
              </h1>
              <p className="text-gray-400 text-sm mt-2 font-mono">DEFENSE MONITORING PROTOCOL v4.2 — NSL-KDD / RANDOM FOREST ENGINE</p>
            </div>
            <div className="flex items-center gap-3">
              <div className="flex gap-2 mr-4 border-r border-gray-800 pr-4">
                <div className={`px-2 py-1 rounded text-[10px] font-mono border flex items-center gap-1.5 ${
                  apiStatus?.gemini
                    ? 'bg-green-500/10 border-green-500/50 text-green-400'
                    : 'bg-red-500/10 border-red-500/50 text-red-400'
                }`}>
                  <div className={`w-1.5 h-1.5 rounded-full ${apiStatus?.gemini ? 'bg-green-400 animate-pulse' : 'bg-red-400'}`} />
                  AI REPORT: {apiStatus === null ? '...' : apiStatus.gemini ? 'READY' : 'NOT READY'}
                </div>
                <div className={`px-2 py-1 rounded text-[10px] font-mono border flex items-center gap-1.5 ${
                  apiStatus?.ipstack
                    ? 'bg-green-500/10 border-green-500/50 text-green-400'
                    : 'bg-red-500/10 border-red-500/50 text-red-400'
                }`}>
                  <div className={`w-1.5 h-1.5 rounded-full ${apiStatus?.ipstack ? 'bg-green-400 animate-pulse' : 'bg-red-400'}`} />
                  GEO MAPPING: {apiStatus === null ? '...' : apiStatus.ipstack ? 'READY' : 'NOT READY'}
                </div>
              </div>
              <SimulationRunner onPrediction={handleSimulationPrediction} disabled={loading} />
              <SocModeButton onClick={() => setSocMode(!socMode)} active={socMode} />
              <div className="flex items-center gap-3 bg-green-500/20 border border-green-500 rounded-lg px-6 py-3 shadow-[0_0_15px_rgba(34,197,94,0.5)]">
                <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse" />
                <span className="text-green-400 font-bold font-mono text-sm">SYSTEM ACTIVE</span>
              </div>
            </div>
          </div>
        </header>

        {/* Error banner */}
        {error && (
          <div className="mb-4 p-3 bg-red-900/40 border border-red-500/50 rounded-lg text-red-400 font-mono text-sm flex items-center gap-2">
            <span>⚠</span>
            <span>{error} — Make sure Flask backend is running on port 5000</span>
          </div>
        )}

        {/* Tab Navigation */}
        <div className="flex gap-1 mb-6 border-b border-gray-800">
          {tabBtn('single', '◉ SINGLE ANALYSIS')}
          {tabBtn('batch', '◫ BATCH ANALYSIS')}
          {tabBtn('uba', '👥 UBA MONITORING')}
        </div>

        {activeTab === 'single' ? (
          <>
            {/* Main Grid */}
            <div className={`grid gap-6 ${socMode ? 'grid-cols-3' : 'grid-cols-1 lg:grid-cols-12'}`}>
              {/* Left: Control Panel */}
              <div className={socMode ? '' : 'lg:col-span-3'}>
                <ControlPanel
                  onPredict={predictAndRecord}
                  loading={loading}
                  confidenceThreshold={ctx.confidenceThreshold}
                  onThresholdChange={ctx.setConfidenceThreshold}
                />
              </div>

              {/* Center */}
              <div className={`space-y-6 ${socMode ? '' : 'lg:col-span-6'}`}>
                <div className="flex justify-center">
                  <ThreatLevelDisplay level={threatLevel} result={result} confidenceThreshold={ctx.confidenceThreshold} />
                </div>
                <AnalyticsPanel threatProbability={threatProbability} result={result} loading={loading} />
                <AttackWorldMap lastResult={result} />

                {/* Network Graph (shows on DoS/Probe) */}
                <NetworkGraph
                  attackType={result?.attack_type || 'Normal'}
                  threatProbability={result?.confidence || 0}
                  visible={!!result}
                />

                {/* Heatmap */}
                <AttackHeatmap />

                <ModelComparison />
              </div>

              {/* Right: Radar + Terminal */}
              <div className={`space-y-6 ${socMode ? '' : 'lg:col-span-3'}`}>
                <div className="bg-black/50 border border-cyan-500/30 rounded-lg p-4 threat-panel">
                  <h3 className="text-cyan-400 text-xs mb-4 font-mono tracking-wider">RADAR SURVEILLANCE</h3>
                  <div className="flex justify-center"><RadarSweep threatLevel={threatLevel} /></div>
                </div>
                <div>
                  <h3 className="text-cyan-400 text-xs mb-2 font-mono tracking-wider">LIVE MONITORING</h3>
                  <TerminalLog threatLevel={threatLevel} lastPrediction={result} />
                </div>
              </div>
            </div>

            {/* Live Threat Feed */}
            <LiveThreatFeed />

            {/* Prediction History */}
            <PredictionHistory entries={history} onClear={() => setHistory([])} />
          </>
        ) : activeTab === 'batch' ? (
          /* Batch Analysis Tab */
          <BatchAnalysis />
        ) : (
          /* UBA Dashboard Tab */
          <UbaDashboard />
        )}

        {/* Footer */}
        <footer className="mt-6 bg-black/50 border border-cyan-500/30 rounded-lg p-4 threat-panel">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-center font-mono text-xs">
            <div><span className="text-gray-400">Model: </span><span className="text-cyan-400 font-bold">RANDOM FOREST</span></div>
            <div><span className="text-gray-400">Accuracy: </span><span className="text-green-400 font-bold">99%+</span></div>
            <div><span className="text-gray-400">Dataset: </span><span className="text-cyan-400 font-bold">NSL-KDD</span></div>
            <div><span className="text-gray-400">Status: </span><span className="text-green-400 font-bold">{loading ? 'SCANNING...' : 'READY'}</span></div>
          </div>
        </footer>
      </div>
    </div>
  );

  const ariaContext = {
    lastThreat: result?.threat,
    lastAttackType: result?.attack_type,
    lastConfidence: result?.confidence,
    isAnomalous: result?.is_anomalous,
    shapValues: result?.shap_values,
  };

  return (
    <SocModeWrapper enabled={socMode}>
      {dashboard}
      <AriaChatbot dashboardContext={ariaContext} />
    </SocModeWrapper>
  );
}
