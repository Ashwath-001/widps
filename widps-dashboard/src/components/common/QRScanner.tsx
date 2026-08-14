/**
 * QR Code Scanner for AP Trust Enrollment
 * =========================================
 * Uses the device camera to scan QR codes containing AP data.
 * Expected QR format: JSON string {"ssid":"NetworkName","bssid":"AA:BB:CC:DD:EE:FF"}
 *
 * On successful scan, POSTs to /api/whitelist to add the trusted AP.
 */

import { useState, useRef, useEffect, useCallback } from 'react';
import { CheckCircle2, XCircle, QrCode } from 'lucide-react';

interface QRScannerProps {
  onSuccess: (ssid: string, bssid: string) => void;
  onClose: () => void;
}

export default function QRScanner({ onSuccess, onClose }: QRScannerProps) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(true);
  const [result, setResult] = useState<{ ssid: string; bssid: string } | null>(null);
  const animFrameRef = useRef<number>(0);

  const startCamera = useCallback(async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment', width: { ideal: 640 }, height: { ideal: 480 } },
      });
      streamRef.current = stream;
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        videoRef.current.play();
      }
    } catch (e) {
      setError('Camera access denied. Allow camera permission to scan QR codes.');
      setScanning(false);
    }
  }, []);

  const stopCamera = useCallback(() => {
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((t) => t.stop());
      streamRef.current = null;
    }
    if (animFrameRef.current) {
      cancelAnimationFrame(animFrameRef.current);
    }
  }, []);

  const scanFrame = useCallback(() => {
    if (!videoRef.current || !canvasRef.current || !scanning) return;

    const video = videoRef.current;
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx || video.readyState !== video.HAVE_ENOUGH_DATA) {
      animFrameRef.current = requestAnimationFrame(scanFrame);
      return;
    }

    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    ctx.drawImage(video, 0, 0);

    // Use BarcodeDetector API (available in Chrome/Edge)
    if ('BarcodeDetector' in window) {
      const detector = new (window as any).BarcodeDetector({ formats: ['qr_code'] });
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

      detector.detect(imageData).then((codes: any[]) => {
        if (codes.length > 0) {
          handleQRData(codes[0].rawValue);
        }
      }).catch(() => {});
    }

    if (scanning) {
      animFrameRef.current = requestAnimationFrame(scanFrame);
    }
  }, [scanning]);

  const handleQRData = (data: string) => {
    try {
      const parsed = JSON.parse(data);
      if (parsed.ssid && parsed.bssid) {
        setResult({ ssid: parsed.ssid, bssid: parsed.bssid });
        setScanning(false);
        stopCamera();
        onSuccess(parsed.ssid, parsed.bssid);
      } else {
        setError('QR code does not contain valid AP data (need ssid + bssid)');
      }
    } catch {
      // Try parsing as "SSID|BSSID" format
      const parts = data.split('|');
      if (parts.length === 2 && parts[1].match(/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/)) {
        setResult({ ssid: parts[0], bssid: parts[1] });
        setScanning(false);
        stopCamera();
        onSuccess(parts[0], parts[1]);
      } else {
        setError('Invalid QR format. Expected: {"ssid":"...","bssid":"AA:BB:CC:DD:EE:FF"}');
      }
    }
  };

  useEffect(() => {
    startCamera();
    return () => stopCamera();
  }, [startCamera, stopCamera]);

  useEffect(() => {
    if (scanning && videoRef.current) {
      const timer = setTimeout(() => {
        animFrameRef.current = requestAnimationFrame(scanFrame);
      }, 500);
      return () => clearTimeout(timer);
    }
  }, [scanning, scanFrame]);

  // Manual input fallback
  const [manualSsid, setManualSsid] = useState('');
  const [manualBssid, setManualBssid] = useState('');

  const handleManualSubmit = () => {
    if (manualSsid && manualBssid.match(/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/i)) {
      onSuccess(manualSsid, manualBssid);
      setResult({ ssid: manualSsid, bssid: manualBssid });
    } else {
      setError('Enter valid SSID and BSSID (format: AA:BB:CC:DD:EE:FF)');
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
      <div className="bg-[var(--color-bg-elevated)] rounded-xl border border-[var(--color-border)] max-w-md w-full overflow-hidden">
        {/* Header */}
        <div className="p-4 border-b border-[var(--color-border)] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <QrCode size={18} className="text-[var(--color-accent-blue)]" />
            <h3 className="text-sm font-semibold">Add Trusted AP</h3>
          </div>
          <button onClick={() => { stopCamera(); onClose(); }} className="text-[var(--color-text-muted)] hover:text-[var(--color-text)]">
            <XCircle size={18} />
          </button>
        </div>

        {/* Camera / Result */}
        <div className="p-4">
          {scanning && !error && (
            <div className="relative aspect-[4/3] rounded-lg overflow-hidden bg-black">
              <video ref={videoRef} className="w-full h-full object-cover" playsInline muted />
              <canvas ref={canvasRef} className="hidden" />
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="w-48 h-48 border-2 border-[var(--color-accent-blue)] rounded-lg opacity-60" />
              </div>
              <p className="absolute bottom-2 left-0 right-0 text-center text-xs text-white/70">
                Point camera at AP QR code
              </p>
            </div>
          )}

          {result && (
            <div className="flex items-center gap-3 p-4 rounded-lg bg-green-500/10 border border-green-500/30">
              <CheckCircle2 size={24} className="text-green-400 shrink-0" />
              <div>
                <p className="text-sm font-medium text-green-400">AP Added to Whitelist</p>
                <p className="text-xs text-[var(--color-text-muted)] mt-0.5">
                  SSID: {result.ssid} | BSSID: {result.bssid}
                </p>
              </div>
            </div>
          )}

          {error && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-400">
              {error}
            </div>
          )}

          {/* Manual fallback */}
          <div className="mt-4 pt-4 border-t border-[var(--color-border-soft)]">
            <p className="text-[10px] text-[var(--color-text-muted)] uppercase mb-2">Or enter manually:</p>
            <div className="flex flex-col gap-2">
              <input
                type="text"
                placeholder="SSID (e.g. CollegeWiFi)"
                value={manualSsid}
                onChange={(e) => setManualSsid(e.target.value)}
                className="px-3 py-2 rounded-lg text-xs bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-accent-blue)]"
              />
              <input
                type="text"
                placeholder="BSSID (e.g. AA:BB:CC:DD:EE:FF)"
                value={manualBssid}
                onChange={(e) => setManualBssid(e.target.value)}
                className="px-3 py-2 rounded-lg text-xs bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-accent-blue)] font-mono"
              />
              <button
                onClick={handleManualSubmit}
                className="px-4 py-2 rounded-lg bg-[var(--color-accent-blue)] text-white text-xs font-medium hover:opacity-90 transition-opacity"
              >
                Add to Whitelist
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
