import { Router } from "express";
import { queryAudit } from "../audit/audit.service.js";

export const auditRouter = Router();

// Mounted behind authenticate + requireRole("admin").
auditRouter.get("/", async (req, res, next) => {
  try {
    const rawSince = req.query["since"];
    const since = rawSince ? new Date(isNaN(Number(rawSince)) ? String(rawSince) : Number(rawSince)) : new Date(0);
    const limit = req.query["limit"] ? Number(req.query["limit"]) : 100;
    const entries = await queryAudit({ since, limit });
    res.json({ count: entries.length, entries });
  } catch (err) {
    next(err);
  }
});
