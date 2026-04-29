import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { io, Socket } from 'socket.io-client';
import { Play, Square } from 'lucide-react';

interface LiveThreatData {
  id: string;
  timestamp: string;
  threatLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  attackType: string;
  confidence: number;
}

export const LiveThreatFeed: React.FC = () => {
  const [feed, setFeed] = useState<LiveThreatData[]>([]);
  const [isActive, setIsActive] = useState(false);
  const socketRef = useRef<Socket | null>(null);

  useEffect(() => {
    // Connect to WebSocket
    socketRef.current = io('http://localhost:5000', {
      transports: ['websocket', 'polling'],
    });

    socketRef.current.on('connect', () => {
      console.log('Live threat feed connected');
    });

    socketRef.current.on('live_threat', (data: any) => {
      const newEntry: LiveThreatData = {
        id: `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
        timestamp: new Date().toLocaleTimeString(),
        threatLevel: data.threat,
        attackType: data.attack_type || 'Unknown',
        confidence: data.confidence,
      };

      setFeed((prev) => {
        const newFeed = [newEntry, ...prev];
        return newFeed.slice(0, 20); // Keep only last 20
      });
    });

    return () => {
      socketRef.current?.disconnect();
    };
  }, []);

  const toggleFeed = () => {
    if (isActive) {
      socketRef.current?.emit('stop_feed');
      setIsActive(false);
    } else {
      socketRef.current?.emit('start_feed');
      setIsActive(true);
    }
  };

  const getThreatColor = (level: string) => {
    switch (level) {
      case 'HIGH': return 'text-red-400 border-red-500/30 bg-red-900/20';
      case 'MEDIUM': return 'text-yellow-400 border-yellow-500/30 bg-yellow-900/20';
      default: return 'text-green-400 border-green-500/30 bg-green-900/20';
    }
  };

  return (
    <div className="bg-black/50 border border-cyan-500/30 rounded-lg p-4 threat-panel mb-6 mt-6">
      <div className="flex items-center justify-between mb-4 border-b border-gray-800 pb-2">
        <h3 className="text-cyan-400 text-xs font-mono tracking-wider flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${isActive ? 'bg-red-500 animate-pulse' : 'bg-gray-500'}`} />
          LIVE THREAT WEBSOCKET FEED
        </h3>
        <button
          onClick={toggleFeed}
          className={`flex items-center gap-2 px-3 py-1.5 text-xs font-mono rounded border transition-all ${
            isActive 
              ? 'bg-red-500/10 text-red-400 border-red-500/50 hover:bg-red-500/20' 
              : 'bg-green-500/10 text-green-400 border-green-500/50 hover:bg-green-500/20'
          }`}
        >
          {isActive ? <Square size={12} /> : <Play size={12} />}
          {isActive ? 'STOP FEED' : 'START FEED'}
        </button>
      </div>

      <div className="h-64 overflow-hidden relative">
        {feed.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center text-gray-500 font-mono text-sm">
            {isActive ? 'WAITING FOR PACKETS...' : 'FEED STOPPED. PRESS START.'}
          </div>
        )}
        
        <div className="flex flex-col gap-2 h-full overflow-y-auto pr-2 custom-scrollbar">
          <AnimatePresence initial={false}>
            {feed.map((entry) => (
              <motion.div
                key={entry.id}
                initial={{ opacity: 0, y: -20, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                transition={{ duration: 0.3 }}
                className={`p-3 rounded border font-mono text-sm grid grid-cols-4 gap-4 items-center ${getThreatColor(entry.threatLevel)}`}
              >
                <div className="text-gray-400 text-xs">{entry.timestamp}</div>
                <div className="font-bold">{entry.threatLevel}</div>
                <div>{entry.attackType}</div>
                <div className="text-right">{entry.confidence.toFixed(1)}%</div>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
};
