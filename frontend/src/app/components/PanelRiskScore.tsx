import React, { useMemo } from 'react';
import { THREAT_CONSTRAINTS, ThreatLevel, THREAT_COLORS } from '../../config/threatConstraints';

const LEVEL_SCORE: Record<ThreatLevel, number> = {
  LOW: 1, MEDIUM: 3, HIGH: 7, CRITICAL: 10,
};

interface Props {
  values: Record<string, any>;
}

export function PanelRiskScore({ values }: Props) {
  const { pct, dominantLevel, highFields } = useMemo(() => {
    let score = 0;
    let maxScore = 0;
    const highFields: string[] = [];
    let dominantLevel: ThreatLevel = 'LOW';
    let maxLevelScore = 0;

    THREAT_CONSTRAINTS.forEach(c => {
      const level = c.evaluate(values[c.field], values);
      if (!level) return;
      const s = LEVEL_SCORE[level];
      score += s;
      maxScore += LEVEL_SCORE['CRITICAL'];
      if (s > maxLevelScore) { maxLevelScore = s; dominantLevel = level; }
      if (level === 'HIGH' || level === 'CRITICAL') highFields.push(c.label);
    });

    return { pct: maxScore > 0 ? Math.round((score / maxScore) * 100) : 0, dominantLevel, highFields };
  }, [values]);

  const color = THREAT_COLORS[dominantLevel];

  return (
    <div
      className="rounded-lg p-3 mb-4"
      style={{ background: 'rgba(0,0,0,0.3)', border: `1px solid ${color}44` }}
    >
      <div className="flex justify-between items-center mb-2">
        <span className="text-[10px] text-gray-500 font-mono tracking-wider">PANEL RISK SCORE</span>
        <span className="text-lg font-bold font-mono" style={{ color }}>
          {pct}%
          <span className="text-[10px] text-gray-500 font-normal ml-2">{dominantLevel}</span>
        </span>
      </div>

      <div className="h-1 bg-white/5 rounded-full overflow-hidden mb-2">
        <div
          className="h-full rounded-full transition-all duration-400"
          style={{ width: `${pct}%`, background: color }}
        />
      </div>

      {highFields.length > 0 ? (
        <div className="text-[9px] font-mono" style={{ color: THREAT_COLORS['HIGH'] }}>
          ▲ HIGH: {highFields.join(' · ')}
        </div>
      ) : (
        <div className="text-[9px] font-mono" style={{ color: THREAT_COLORS['LOW'] }}>
          ✓ All parameters within normal range
        </div>
      )}
    </div>
  );
}
