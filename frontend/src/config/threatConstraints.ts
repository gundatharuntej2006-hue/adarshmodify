export type ThreatLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface FieldConstraint {
  field: string;
  label: string;
  evaluate: (value: any, allValues?: Record<string, any>) => ThreatLevel | null;
  description: Record<string, string>;
}

export const THREAT_CONSTRAINTS: FieldConstraint[] = [
  {
    field: "protocol_type",
    label: "Protocol Type",
    evaluate: (val) => {
      if (!val) return null;
      const v = val.toString().toUpperCase();
      if (v === "ICMP") return "HIGH";
      if (v === "UDP")  return "MEDIUM";
      return "LOW";
    },
    description: {
      LOW: "TCP is standard — lower risk",
      MEDIUM: "UDP can be used in flood attacks",
      HIGH: "ICMP often used in ping sweeps and recon",
    },
  },
  {
    field: "flag",
    label: "Connection Flag",
    evaluate: (val) => {
      if (!val) return null;
      const v = val.toString().toUpperCase().replace(" (NORMAL)", "");
      if (v === "SF") return "LOW";
      if (["REJ", "RSTO", "OTH"].includes(v)) return "MEDIUM";
      if (["S0", "SH", "S1", "S2", "S3", "RSTOS0", "RSTR"].includes(v)) return "HIGH";
      return "MEDIUM";
    },
    description: {
      LOW: "SF = normal completed connection",
      MEDIUM: "Connection was reset or rejected",
      HIGH: "S0/SH = SYN sent, no response — DoS indicator",
    },
  },
  {
    field: "num_failed_logins",
    label: "Failed Logins",
    evaluate: (val) => {
      const n = Number(val);
      if (isNaN(n) || n === 0) return "LOW";
      if (n <= 4) return "MEDIUM";
      return "HIGH";
    },
    description: {
      LOW: "No failed login attempts",
      MEDIUM: "Some failed logins — credential testing",
      HIGH: "5+ failures — brute force attack (R2L)",
    },
  },
  {
    field: "src_bytes",
    label: "SRC Bytes",
    evaluate: (val) => {
      const n = Number(val);
      if (isNaN(n)) return null;
      if (n < 1000)   return "LOW";
      if (n < 100000)  return "MEDIUM";
      return "HIGH";
    },
    description: {
      LOW: "Normal data volume",
      MEDIUM: "Elevated data transfer",
      HIGH: "Very high bytes — possible DoS or exfiltration",
    },
  },
  {
    field: "dst_bytes",
    label: "DST Bytes",
    evaluate: (val) => {
      const n = Number(val);
      if (isNaN(n)) return null;
      if (n < 5000)   return "LOW";
      if (n < 500000)  return "MEDIUM";
      return "HIGH";
    },
    description: {
      LOW: "Normal response volume",
      MEDIUM: "Large response — monitor",
      HIGH: "Extremely large — investigate immediately",
    },
  },
  {
    field: "logged_in",
    label: "Logged In",
    evaluate: (val) => {
      if (val === 1 || val === "1" || val?.toString().toUpperCase() === "YES") return "LOW";
      if (val === 0 || val === "0" || val?.toString().toUpperCase() === "NO")  return "HIGH";
      return null;
    },
    description: {
      LOW: "User is authenticated — normal",
      MEDIUM: "Unknown auth state",
      HIGH: "Unauthenticated — possible intrusion attempt",
    },
  },
  {
    field: "root_shell",
    label: "Root Shell",
    evaluate: (val) => {
      if (val === 1 || val === "1" || val?.toString().toUpperCase() === "YES") return "CRITICAL";
      if (val === 0 || val === "0" || val?.toString().toUpperCase() === "NO")  return "LOW";
      return null;
    },
    description: {
      LOW: "No root shell — normal",
      MEDIUM: "Partial escalation detected",
      HIGH: "Root shell obtained — U2R attack!",
      CRITICAL: "CRITICAL: Root shell = active compromise",
    },
  },
  {
    field: "count",
    label: "Count",
    evaluate: (val) => {
      const n = Number(val);
      if (isNaN(n)) return null;
      if (n < 50)  return "LOW";
      if (n < 200) return "MEDIUM";
      return "HIGH";
    },
    description: {
      LOW: "Normal connection frequency",
      MEDIUM: "Elevated connections to same host",
      HIGH: "Very high count — DoS pattern",
    },
  },
  {
    field: "srv_count",
    label: "SRV Count",
    evaluate: (val) => {
      const n = Number(val);
      if (isNaN(n)) return null;
      if (n < 50)  return "LOW";
      if (n < 300) return "MEDIUM";
      return "HIGH";
    },
    description: {
      LOW: "Normal service request rate",
      MEDIUM: "Elevated service requests",
      HIGH: "Service flood — likely DoS",
    },
  },
  {
    field: "serror_rate",
    label: "Error Rate (SYN/Flood)",
    evaluate: (val) => {
      const n = Number(val);
      if (isNaN(n)) return null;
      if (n <= 0.1) return "LOW";
      if (n <= 0.5) return "MEDIUM";
      return "HIGH";
    },
    description: {
      LOW: "Very few SYN errors — normal",
      MEDIUM: "Some SYN errors — possible scanning",
      HIGH: "High SYN error rate — DoS attack",
    },
  },
  {
    field: "dst_host_count",
    label: "DST Host Count",
    evaluate: (val) => {
      const n = Number(val);
      if (isNaN(n)) return null;
      if (n < 50)  return "LOW";
      if (n < 200) return "MEDIUM";
      return "HIGH";
    },
    description: {
      LOW: "Connecting to few hosts — normal",
      MEDIUM: "Multiple hosts contacted — possible scan",
      HIGH: "200+ hosts — network sweep / Probe",
    },
  },
  {
    field: "duration",
    label: "Duration",
    evaluate: (val) => {
      const n = Number(val);
      if (isNaN(n)) return null;
      if (n === 0) return "LOW";
      if (n <= 300) return "MEDIUM";
      return "HIGH";
    },
    description: {
      LOW: "Instant connection — typical HTTP",
      MEDIUM: "Medium-length session",
      HIGH: "Long session — possible backdoor",
    },
  },
];

export const THREAT_COLORS: Record<ThreatLevel, string> = {
  LOW:      "#1D9E75",
  MEDIUM:   "#EF9F27",
  HIGH:     "#E24B4A",
  CRITICAL: "#FF0055",
};

export const THREAT_BG: Record<ThreatLevel, string> = {
  LOW:      "rgba(29, 158, 117, 0.12)",
  MEDIUM:   "rgba(239, 159, 39, 0.12)",
  HIGH:     "rgba(226, 75, 74, 0.12)",
  CRITICAL: "rgba(255, 0, 85, 0.15)",
};

export const THREAT_BORDER: Record<ThreatLevel, string> = {
  LOW:      "rgba(29, 158, 117, 0.35)",
  MEDIUM:   "rgba(239, 159, 39, 0.35)",
  HIGH:     "rgba(226, 75, 74, 0.35)",
  CRITICAL: "rgba(255, 0, 85, 0.5)",
};
