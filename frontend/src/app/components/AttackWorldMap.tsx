import { useEffect, useState, useMemo } from 'react';
import { GoogleMap, useJsApiLoader, OverlayView, Polyline, InfoWindow } from '@react-google-maps/api';
import { ThreatResponse } from '../../api/threatApi';
import { io } from 'socket.io-client';

interface AttackWorldMapProps {
  lastResult: ThreatResponse | null;
}

const ATTACK_COLORS: Record<string, string> = {
  Normal: '#10b981',
  DoS: '#ef4444',
  Probe: '#eab308',
  R2L: '#f97316',
  U2R: '#a855f7',
};

const mapStyles = [
  { elementType: "geometry", stylers: [{ color: "#1d2c4d" }] },
  { elementType: "labels.text.fill", stylers: [{ color: "#8ec3b9" }] },
  { elementType: "labels.text.stroke", stylers: [{ color: "#1a3646" }] },
  { featureType: "administrative.country", elementType: "geometry.stroke", stylers: [{ color: "#4b6878" }] },
  { featureType: "administrative.land_parcel", elementType: "labels.text.fill", stylers: [{ color: "#64779e" }] },
  { featureType: "administrative.province", elementType: "geometry.stroke", stylers: [{ color: "#4b6878" }] },
  { featureType: "landscape.man_made", elementType: "geometry.stroke", stylers: [{ color: "#334e87" }] },
  { featureType: "landscape.natural", elementType: "geometry", stylers: [{ color: "#023e58" }] },
  { featureType: "poi", elementType: "geometry", stylers: [{ color: "#283d6a" }] },
  { featureType: "poi", elementType: "labels.text.fill", stylers: [{ color: "#6f9ba5" }] },
  { featureType: "poi", elementType: "labels.text.stroke", stylers: [{ color: "#1d2c4d" }] },
  { featureType: "poi.park", elementType: "geometry.fill", stylers: [{ color: "#023e58" }] },
  { featureType: "poi.park", elementType: "labels.text.fill", stylers: [{ color: "#3C7680" }] },
  { featureType: "road", elementType: "geometry", stylers: [{ color: "#304a7d" }] },
  { featureType: "road", elementType: "labels.text.fill", stylers: [{ color: "#98a5be" }] },
  { featureType: "road", elementType: "labels.text.stroke", stylers: [{ color: "#1d2c4d" }] },
  { featureType: "road.highway", elementType: "geometry", stylers: [{ color: "#2c6675" }] },
  { featureType: "road.highway", elementType: "geometry.stroke", stylers: [{ color: "#255763" }] },
  { featureType: "road.highway", elementType: "labels.text.fill", stylers: [{ color: "#b0d5ce" }] },
  { featureType: "road.highway", elementType: "labels.text.stroke", stylers: [{ color: "#023e58" }] },
  { featureType: "transit", elementType: "labels.text.fill", stylers: [{ color: "#98a5be" }] },
  { featureType: "transit", elementType: "labels.text.stroke", stylers: [{ color: "#1d2c4d" }] },
  { featureType: "transit.line", elementType: "geometry.fill", stylers: [{ color: "#283d6a" }] },
  { featureType: "transit.station", elementType: "geometry", stylers: [{ color: "#3a4762" }] },
  { featureType: "water", elementType: "geometry", stylers: [{ color: "#0e1626" }] },
  { featureType: "water", elementType: "labels.text.fill", stylers: [{ color: "#4e6d70" }] }
];

export function AttackWorldMap({ lastResult }: AttackWorldMapProps) {
  const { isLoaded } = useJsApiLoader({
    id: 'google-map-script',
    googleMapsApiKey: import.meta.env.VITE_GOOGLE_MAPS_API_KEY || ''
  });

  const [markers, setMarkers] = useState<any[]>([]);
  const [beams, setBeams] = useState<any[]>([]);
  const [selectedMarker, setSelectedMarker] = useState<any>(null);
  
  const [stats, setStats] = useState({
    Normal: 0, DoS: 0, Probe: 0, R2L: 0, U2R: 0, Total: 0
  });

  const center = useMemo(() => ({ lat: 20, lng: 0 }), []);
  const options = useMemo(() => ({
    styles: mapStyles,
    disableDefaultUI: true,
    zoomControl: false,
    streetViewControl: false,
    mapTypeControl: false,
    backgroundColor: '#0d1117'
  }), []);

  useEffect(() => {
    if (lastResult?.location) {
      const type = lastResult.attack_type || 'Normal';
      const newMarker = {
        lat: lastResult.location.lat,
        lng: lastResult.location.lng,
        type: type,
        country: lastResult.location.country || 'Unknown',
        city: lastResult.location.city || 'Unknown',
        threat_level: lastResult.threat,
        confidence: lastResult.confidence,
        timestamp: new Date().toLocaleTimeString(),
        id: Date.now()
      };
      
      setStats(prev => ({
        ...prev,
        [type]: (prev[type as keyof typeof prev] || 0) + 1,
        Total: prev.Total + 1
      }));

      setMarkers(prev => [...prev, newMarker].slice(-5));
      
      const timer = setTimeout(() => {
        setMarkers(prev => prev.filter(m => m.id !== newMarker.id));
        if (selectedMarker?.id === newMarker.id) {
          setSelectedMarker(null);
        }
      }, 5000);

      if (lastResult.threat === 'HIGH') {
        const newBeam = { id: newMarker.id, lat: newMarker.lat, lng: newMarker.lng };
        setBeams(prev => [...prev, newBeam]);
        setTimeout(() => {
          setBeams(prev => prev.filter(b => b.id !== newBeam.id));
        }, 3000);
      }

      return () => clearTimeout(timer);
    }
  }, [lastResult, selectedMarker]);

  useEffect(() => {
    const socket = io('http://localhost:5000', {
      transports: ['websocket', 'polling'],
    });

    socket.on('live_threat', (data: any) => {
      if (data.location) {
        const type = data.attack_type || 'Normal';
        const newMarker = {
          lat: data.location.lat,
          lng: data.location.lng,
          type: type,
          country: data.location.country || 'Unknown',
          city: data.location.city || 'Unknown',
          threat_level: data.threat,
          confidence: data.confidence,
          timestamp: new Date().toLocaleTimeString(),
          id: Date.now() + Math.random() // Ensure unique ID for rapid events
        };

        setStats(prev => ({
          ...prev,
          [type]: (prev[type as keyof typeof prev] || 0) + 1,
          Total: prev.Total + 1
        }));

        setMarkers(prev => [...prev, newMarker].slice(-30)); // Max 30 markers for burst mode

        if (data.threat === 'HIGH') {
          const newBeam = { id: newMarker.id, lat: newMarker.lat, lng: newMarker.lng };
          setBeams(prev => [...prev, newBeam].slice(-30));
          setTimeout(() => {
            setBeams(prev => prev.filter(b => b.id !== newBeam.id));
          }, 3000);
        }

        setTimeout(() => {
          setMarkers(prev => prev.filter(m => m.id !== newMarker.id));
        }, 5000);
      }
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  if (!isLoaded) return <div className="w-full h-full bg-gray-900/50 border border-cyan-500/10 rounded animate-pulse" />;

  return (
    <div className="bg-black/50 border border-cyan-500/30 rounded-lg p-4 threat-panel overflow-hidden">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-cyan-400 text-xs font-mono tracking-wider">GLOBAL THREAT MAP (LIVE)</h3>
        <div className="flex gap-2 text-[10px] font-mono">
          <span className="text-red-400">● HIGH THREAT</span>
          <span className="text-cyan-400">● LIVE MAP</span>
        </div>
      </div>

      <div className="relative aspect-[2/1] rounded overflow-hidden" style={{ border: '1px solid rgba(0,255,255,0.3)', boxShadow: '0 0 20px rgba(0,255,255,0.15)' }}>
        <GoogleMap
          mapContainerStyle={{ width: '100%', height: '100%' }}
          center={center}
          zoom={2}
          options={options}
        >
          {markers.map(m => {
            const color = ATTACK_COLORS[m.type] || '#fff';
            return (
              <OverlayView
                key={m.id}
                position={{ lat: m.lat, lng: m.lng }}
                mapPaneName={OverlayView.OVERLAY_MOUSE_TARGET}
              >
                <div className="absolute -translate-x-1/2 -translate-y-1/2 cursor-pointer" onClick={() => setSelectedMarker(m)}>
                  <div 
                    className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 rounded-full opacity-75"
                    style={{ 
                      backgroundColor: color,
                      animation: 'pulse-ring 1.5s infinite ease-out'
                    }}
                  />
                  <div
                    className="relative z-10 w-3 h-3 rounded-full shadow-[0_0_10px_rgba(255,255,255,0.8)]"
                    style={{ backgroundColor: color }}
                  />
                  <div className="absolute top-4 left-1/2 -translate-x-1/2 whitespace-nowrap bg-[#0d1117]/90 px-2 py-1 rounded border border-cyan-500/40 text-[10px] font-mono text-cyan-400 animate-bounce pointer-events-none shadow-lg">
                    {m.type} @ {m.country}
                  </div>
                </div>
              </OverlayView>
            );
          })}

          {beams.map(b => (
            <Polyline
              key={b.id}
              path={[{ lat: b.lat, lng: b.lng }, center]}
              options={{
                strokeColor: '#ef4444',
                strokeOpacity: 0.8,
                strokeWeight: 2,
                geodesic: true,
              }}
            />
          ))}

          {selectedMarker && (
            <InfoWindow
              position={{ lat: selectedMarker.lat, lng: selectedMarker.lng }}
              onCloseClick={() => setSelectedMarker(null)}
              options={{ pixelOffset: new window.google.maps.Size(0, -15) }}
            >
              <div className="bg-[#0d1117] text-gray-300 font-mono text-xs p-2 rounded shadow-xl border border-cyan-500/50" style={{ minWidth: '180px' }}>
                <div className="text-cyan-400 mb-1 border-b border-cyan-500/30 pb-1">🌍 {selectedMarker.city || 'Unknown'}, {selectedMarker.country}</div>
                <div>🚨 Threat: <span style={{ color: ATTACK_COLORS[selectedMarker.type] || '#fff' }}>{selectedMarker.threat_level}</span></div>
                <div>⚔️ Type: {selectedMarker.type}</div>
                <div>📊 Confidence: {(selectedMarker.confidence * 100).toFixed(1)}%</div>
                <div className="text-gray-500 mt-1 pt-1 border-t border-gray-800">🕐 {selectedMarker.timestamp}</div>
              </div>
            </InfoWindow>
          )}
        </GoogleMap>

        {/* Stats Overlay */}
        <div className="absolute top-4 left-4 z-10 bg-black/75 backdrop-blur-md border border-cyan-500/20 rounded-lg p-3 font-mono text-[10px] shadow-xl">
          <div className="text-cyan-400 mb-1 font-bold">LIVE METRICS</div>
          <div className="text-red-400">🔴 DoS: {stats.DoS}</div>
          <div className="text-yellow-400">🟡 Probe: {stats.Probe}</div>
          <div className="text-orange-400">🟠 R2L: {stats.R2L}</div>
          <div className="text-purple-400">🟣 U2R: {stats.U2R}</div>
          <div className="text-green-400">🟢 Normal: {stats.Normal}</div>
          <div className="border-t border-cyan-500/30 my-1"></div>
          <div className="text-white font-bold tracking-widest">📡 TOTAL: {stats.Total}</div>
        </div>

        <style>{`
          @keyframes pulse-ring {
            0% { width: 12px; height: 12px; opacity: 1; }
            100% { width: 30px; height: 30px; opacity: 0; }
          }
          .gm-style-iw-c { background-color: #0d1117 !important; border-radius: 8px; padding: 0 !important; border: 1px solid rgba(0,255,255,0.3); }
          .gm-style-iw-d { overflow: hidden !important; }
          .gm-style-iw-t::after { display: none; }
          .gm-ui-hover-effect { filter: invert(1); }
        `}</style>
      </div>
    </div>
  );
}
