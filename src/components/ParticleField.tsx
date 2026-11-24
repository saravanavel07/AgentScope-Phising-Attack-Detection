import { useEffect, useRef } from 'react';

interface ParticleFieldProps {
  isScanning?: boolean;
}

interface Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  alpha: number;
  hue: 'electric' | 'arctic' | 'steel';
  history: Array<{ x: number; y: number }>;
}

export function ParticleField({ isScanning = false }: ParticleFieldProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const scanningRef = useRef(isScanning);

  useEffect(() => {
    scanningRef.current = isScanning;
  }, [isScanning]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const mouse = { x: -9999, y: -9999, active: false };

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };

    const handleMouseMove = (e: MouseEvent) => {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
      mouse.active = true;
    };

    const handleMouseLeave = () => {
      mouse.active = false;
    };

    window.addEventListener('resize', handleResize);
    window.addEventListener('mousemove', handleMouseMove, { passive: true });
    window.addEventListener('mouseleave', handleMouseLeave);

    const count = Math.min(72, Math.max(32, Math.floor((width * height) / 22000)));
    const hues: Array<Particle['hue']> = ['electric', 'arctic', 'steel'];

    const particles: Particle[] = Array.from({ length: count }, (_, idx) => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.42,
      vy: (Math.random() - 0.5) * 0.42,
      radius: 1.1 + Math.random() * 2.1,
      alpha: 0.25 + Math.random() * 0.5,
      hue: hues[idx % hues.length],
      history: [],
    }));

    const colorForHue = (hue: Particle['hue'], alpha: number) => {
      if (hue === 'arctic') return `rgba(56, 189, 248, ${alpha})`;
      if (hue === 'electric') return `rgba(59, 130, 246, ${alpha})`;
      return `rgba(148, 163, 184, ${alpha * 0.7})`;
    };

    let animId = 0;

    const drawFrame = () => {
      ctx.clearRect(0, 0, width, height);

      // Soft ambient Gemini-style blue radial aura at top center
      const grad = ctx.createRadialGradient(
        width * 0.5,
        height * 0.08,
        20,
        width * 0.5,
        height * 0.12,
        Math.max(width, height) * 0.55
      );
      grad.addColorStop(0, scanningRef.current ? 'rgba(56, 189, 248, 0.09)' : 'rgba(37, 99, 235, 0.065)');
      grad.addColorStop(0.5, 'rgba(30, 58, 138, 0.025)');
      grad.addColorStop(1, 'rgba(9, 11, 16, 0)');
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, width, height);

      const speedBoost = scanningRef.current ? 2.1 : 1;
      const linkDist = scanningRef.current ? 155 : 130;

      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];

        if (!prefersReducedMotion) {
          p.history.push({ x: p.x, y: p.y });
          if (p.history.length > 5) p.history.shift();

          if (mouse.active) {
            const dx = p.x - mouse.x;
            const dy = p.y - mouse.y;
            const dist = Math.hypot(dx, dy);
            if (dist > 0 && dist < 140) {
              const force = ((140 - dist) / 140) * 0.035;
              p.vx += (dx / dist) * force;
              p.vy += (dy / dist) * force;
            }
          }

          // Gentle velocity damping so interactions settle smoothly
          const maxVel = 0.85 * speedBoost;
          const speed = Math.hypot(p.vx, p.vy);
          if (speed > maxVel) {
            p.vx = (p.vx / speed) * maxVel;
            p.vy = (p.vy / speed) * maxVel;
          }

          p.x += p.vx * speedBoost;
          p.y += p.vy * speedBoost;

          if (p.x < -10) p.x = width + 10;
          if (p.x > width + 10) p.x = -10;
          if (p.y < -10) p.y = height + 10;
          if (p.y > height + 10) p.y = -10;
        }

        // Subtle glowing trail
        for (let t = 0; t < p.history.length; t++) {
          const pt = p.history[t];
          const trailAlpha = ((t + 1) / (p.history.length + 1)) * p.alpha * 0.28;
          ctx.beginPath();
          ctx.arc(pt.x, pt.y, p.radius * 0.65, 0, Math.PI * 2);
          ctx.fillStyle = colorForHue(p.hue, trailAlpha);
          ctx.fill();
        }

        // Core particle glow
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fillStyle = colorForHue(p.hue, p.alpha);
        ctx.shadowColor = p.hue === 'steel' ? 'rgba(96, 165, 250, 0.25)' : 'rgba(56, 189, 248, 0.55)';
        ctx.shadowBlur = p.radius * 4;
        ctx.fill();
        ctx.shadowBlur = 0;

        // Connected network edges
        for (let j = i + 1; j < particles.length; j++) {
          const q = particles[j];
          const dx = p.x - q.x;
          const dy = p.y - q.y;
          const d = Math.hypot(dx, dy);
          if (d < linkDist) {
            const lineAlpha = (1 - d / linkDist) * (scanningRef.current ? 0.22 : 0.13);
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(q.x, q.y);
            ctx.strokeStyle = `rgba(96, 165, 250, ${lineAlpha})`;
            ctx.lineWidth = 0.8;
            ctx.stroke();
          }
        }
      }

      if (!prefersReducedMotion) {
        animId = requestAnimationFrame(drawFrame);
      }
    };

    drawFrame();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseleave', handleMouseLeave);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 z-0 h-full w-full opacity-90"
    />
  );
}
