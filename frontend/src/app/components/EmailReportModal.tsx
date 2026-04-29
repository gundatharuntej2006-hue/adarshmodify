import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'sonner';

interface EmailReportModalProps {
  reportText: string;
  threatLevel: string;
}

export function EmailReportModal({ reportText, threatLevel }: EmailReportModalProps) {
  const [showModal, setShowModal] = useState(false);
  const [email, setEmail] = useState('');
  const [sending, setSending] = useState(false);

  const handleSend = async () => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      toast.error('❌ Failed: Invalid email format');
      return;
    }
    
    setSending(true);
    try {
      const apiUrl = import.meta.env.VITE_API_URL || 'http://127.0.0.1:5000';
      const res = await fetch(`${apiUrl}/send-report-email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: email,
          report: reportText,
          threat_level: threatLevel
        })
      });
      const data = await res.json();
      if (data.success) {
        toast.success('📧 Report sent successfully!');
        setShowModal(false);
      } else {
        toast.error(`❌ Failed: ${data.error || 'Unknown error'}`);
      }
    } catch (err) {
      toast.error('❌ Failed: Network error');
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="inline-block ml-4">
      <button
        onClick={() => setShowModal(true)}
        className="px-4 py-2 text-xs font-mono border border-cyan-500/50 bg-cyan-500/10 text-cyan-400 rounded hover:bg-cyan-500/20 transition-all flex items-center gap-2"
      >
        📧 Send via Email
      </button>

      <AnimatePresence>
        {showModal && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 backdrop-blur-sm" onClick={() => setShowModal(false)}>
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              onClick={(e) => e.stopPropagation()}
              className="bg-[#0a0a0a] border border-cyan-500/40 rounded-lg p-6 max-w-lg w-full mx-4 flex flex-col gap-4 shadow-[0_0_15px_rgba(34,211,238,0.2)]"
            >
              <h3 className="text-cyan-400 font-mono text-sm tracking-wider">Send Incident Report</h3>
              
              <div>
                <input 
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@company.com"
                  className={`w-full bg-black/50 border rounded px-3 py-2 text-sm font-mono text-white focus:outline-none transition-colors ${
                    email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? 'border-red-500 focus:border-red-500' : 'border-gray-700 focus:border-cyan-500'
                  }`}
                />
              </div>

              <div>
                <label className="text-gray-400 text-xs font-mono mb-1 block">REPORT PREVIEW</label>
                <div className="bg-black/50 border border-gray-800 rounded p-4 font-mono text-xs text-gray-300 whitespace-pre-wrap overflow-y-auto max-h-[150px] custom-scrollbar">
                  {reportText}
                </div>
              </div>

              <div className="flex justify-end gap-3 mt-2">
                <button
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 text-xs font-mono border border-gray-600 text-gray-400 rounded hover:bg-gray-700/50 transition-all"
                >
                  Cancel
                </button>
                <button
                  onClick={handleSend}
                  disabled={sending}
                  className="px-4 py-2 text-xs font-mono border border-cyan-500 bg-cyan-500/20 text-cyan-400 rounded hover:bg-cyan-500/40 transition-all flex items-center gap-2 disabled:opacity-50 min-w-[120px] justify-center"
                >
                  {sending ? (
                    <motion.span animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 1, ease: "linear" }} className="inline-block">
                      ⟳
                    </motion.span>
                  ) : (
                    'Send Report'
                  )}
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
