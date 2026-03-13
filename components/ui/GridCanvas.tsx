"use client";

import { useEffect, useRef } from "react";

interface Dot {
  x: number;
  y: number;
  vx: number;
  vy: number;
  r: number;
  alpha: number;
  pulse: number;
  pulseSpeed: number;
}

export function GridCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let raf: number;
    let dots: Dot[] = [];

    function resize() {
      if (!canvas) return;
      canvas.width = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
    }

    function spawnDots() {
      if (!canvas) return;
      dots = Array.from({ length: 28 }, () => ({
        x: Math.random() * canvas!.width,
        y: Math.random() * canvas!.height,
        vx: (Math.random() - 0.5) * 0.25,
        vy: (Math.random() - 0.5) * 0.25,
        r: Math.random() * 1.5 + 0.8,
        alpha: Math.random() * 0.5 + 0.3,
        pulse: Math.random() * Math.PI * 2,
        pulseSpeed: 0.008 + Math.random() * 0.012,
      }));
    }

    function draw() {
      if (!canvas || !ctx) return;
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      const CELL = 60;
      const cols = Math.ceil(canvas.width / CELL) + 1;
      const rows = Math.ceil(canvas.height / CELL) + 1;

      // Grid lines
      ctx.strokeStyle = "rgba(255,196,0,0.045)";
      ctx.lineWidth = 0.5;
      ctx.beginPath();
      for (let c = 0; c <= cols; c++) {
        const x = c * CELL;
        ctx.moveTo(x, 0);
        ctx.lineTo(x, canvas.height);
      }
      for (let r = 0; r <= rows; r++) {
        const y = r * CELL;
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
      }
      ctx.stroke();

      // Center glow
      const cx = canvas.width / 2;
      const cy = canvas.height * 0.4;
      const grd = ctx.createRadialGradient(cx, cy, 0, cx, cy, Math.min(canvas.width, canvas.height) * 0.55);
      grd.addColorStop(0, "rgba(255,196,0,0.07)");
      grd.addColorStop(1, "rgba(0,0,0,0)");
      ctx.fillStyle = grd;
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      // Dots
      for (const d of dots) {
        d.pulse += d.pulseSpeed;
        const alpha = d.alpha * (0.6 + 0.4 * Math.sin(d.pulse));
        ctx.beginPath();
        ctx.arc(d.x, d.y, d.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255,196,0,${alpha})`;
        ctx.fill();

        d.x += d.vx;
        d.y += d.vy;
        if (d.x < -10) d.x = canvas.width + 10;
        if (d.x > canvas.width + 10) d.x = -10;
        if (d.y < -10) d.y = canvas.height + 10;
        if (d.y > canvas.height + 10) d.y = -10;
      }

      raf = requestAnimationFrame(draw);
    }

    const ro = new ResizeObserver(() => { resize(); spawnDots(); });
    ro.observe(canvas);
    resize();
    spawnDots();
    draw();

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="absolute inset-0 w-full h-full pointer-events-none"
      aria-hidden="true"
    />
  );
}
