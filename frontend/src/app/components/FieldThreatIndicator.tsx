import React, { useMemo } from 'react';
import {
  THREAT_CONSTRAINTS,
  ThreatLevel,
  THREAT_COLORS,
  THREAT_BG,
  THREAT_BORDER,
} from '../../config/threatConstraints';

interface Props {
  field: string;
  value: any;
  allValues?: Record<string, any>;
  children: React.ReactNode;
}

export function FieldThreatIndicator({ field, value, allValues, children }: Props) {
  const constraint = THREAT_CONSTRAINTS.find(c => c.field === field);

  const level: ThreatLevel | null = useMemo(() => {
    if (!constraint) return null;
    return constraint.evaluate(value, allValues);
  }, [constraint, value, allValues]);

  const desc   = level && constraint?.description[level];
  const color  = level ? THREAT_COLORS[level] : 'transparent';
  const border = level ? THREAT_BORDER[level] : 'transparent';
  const bg     = level ? THREAT_BG[level] : 'transparent';

  const icons: Record<ThreatLevel, string> = {
    LOW: '✓', MEDIUM: '⚠', HIGH: '▲', CRITICAL: '‼',
  };

  return (
    <div className="w-full">
      {/* Badge row */}
      {level && level !== 'LOW' && (
        <div className="flex items-center justify-end mb-1 gap-1.5">
          <span
            className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono font-bold tracking-wider ${
              level === 'CRITICAL' ? 'animate-pulse' : ''
            }`}
            style={{ background: bg, border: `1px solid ${border}`, color }}
          >
            {icons[level]} {level}
          </span>
        </div>
      )}

      {/* Input with highlighted border */}
      <div
        style={{
          borderRadius: 6,
          outline: level && level !== 'LOW' ? `1px solid ${border}` : undefined,
          transition: 'outline 0.2s ease',
        }}
      >
        {children}
      </div>

      {/* Description bar */}
      {level && level !== 'LOW' && desc && (
        <div className="flex items-center gap-2 mt-1">
          <div className="flex-1 h-0.5 rounded-full bg-white/5 overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-300"
              style={{
                width: level === 'MEDIUM' ? '55%' : level === 'HIGH' ? '80%' : '100%',
                background: color,
              }}
            />
          </div>
          <span
            className="text-[8px] font-mono whitespace-nowrap max-w-[55%] overflow-hidden text-ellipsis"
            style={{ color }}
          >
            {desc}
          </span>
        </div>
      )}
    </div>
  );
}
