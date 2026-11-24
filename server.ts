import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { createServer as createViteServer } from 'vite';
import { analyzeEmail } from './server/engine/emailAnalyzer.ts';
import { analyzeUrl } from './server/engine/urlAnalyzer.ts';
import {
  clearAllReports,
  computeDashboardStats,
  deleteScanReport,
  readAllReports,
  saveScanReport,
} from './server/store/scanStore.ts';

const PORT = Number(process.env.PORT) || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

async function startServer() {
  const app = express();

  app.disable('x-powered-by');
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    next();
  });

  app.use(express.json({ limit: '256kb' }));

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true });
  });

  app.get('/api/stats', async (_req, res) => {
    try {
      const stats = await computeDashboardStats();
      res.json(stats);
    } catch {
      res.status(500).json({ error: 'Failed to load dashboard statistics.' });
    }
  });

  app.get('/api/reports', async (_req, res) => {
    try {
      const reports = await readAllReports();
      res.json({ reports });
    } catch {
      res.status(500).json({ error: 'Failed to load scan reports.' });
    }
  });

  app.post('/api/scan/url', async (req, res) => {
    try {
      const url = typeof req.body?.url === 'string' ? req.body.url : '';
      if (!url.trim() || url.length > 2048) {
        res.status(400).json({ error: 'Provide a valid URL up to 2,048 characters.' });
        return;
      }

      const report = await analyzeUrl(url);
      await saveScanReport(report);
      res.status(200).json({ report });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to complete URL analysis.';
      res.status(400).json({ error: message });
    }
  });

  app.post('/api/scan/email', async (req, res) => {
    try {
      const rawContent = typeof req.body?.rawContent === 'string' ? req.body.rawContent : '';
      const sender = typeof req.body?.sender === 'string' ? req.body.sender : undefined;
      const subject = typeof req.body?.subject === 'string' ? req.body.subject : undefined;

      if (!rawContent.trim() || rawContent.length > 120_000) {
        res.status(400).json({ error: 'Provide email content up to 120,000 characters.' });
        return;
      }

      const report = await analyzeEmail({ rawContent, sender, subject });
      await saveScanReport(report);
      res.status(200).json({ report });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to complete email analysis.';
      res.status(400).json({ error: message });
    }
  });

  app.delete('/api/reports/:id', async (req, res) => {
    try {
      const id = String(req.params.id || '').trim();
      if (!id || id.length > 100) {
        res.status(400).json({ error: 'Invalid report identifier.' });
        return;
      }
      const deleted = await deleteScanReport(id);
      if (!deleted) {
        res.status(404).json({ error: 'Report not found.' });
        return;
      }
      res.json({ deleted: true });
    } catch {
      res.status(500).json({ error: 'Failed to delete scan report.' });
    }
  });

  app.delete('/api/reports', async (_req, res) => {
    try {
      await clearAllReports();
      res.json({ cleared: true });
    } catch {
      res.status(500).json({ error: 'Failed to clear scan history.' });
    }
  });

  if (!IS_PROD) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      const indexPath = path.join(distDir, 'index.html');
      if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
      } else {
        res.status(404).send('Build output not found. Run npm run build first.');
      }
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`AegisTrace server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
