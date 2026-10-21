import path from "node:path";
import type { Express, NextFunction, Request, Response } from "express";
import type { DatabaseSync } from "node:sqlite";
import type { AppContext } from "../app.ts";
import type { BrandMark } from "../branding.ts";
import type { Config } from "../config.ts";
import type { LookState } from "../look.ts";

/**
 * What createApp hands every route module: the app to mount on, the instance's config, database
 * and clock, the AppContext a test may have given fakes through, and the four helpers every route
 * shares — the look this browser chose, who is asking, the owner gate, and whether cookies may be
 * marked Secure. The modules under src/routes/ take exactly this and nothing else.
 */
export interface RouteContext {
  app: Express;
  config: Config;
  db: DatabaseSync;
  now: () => Date;
  ctx: AppContext;
  lookOf: (req: Request) => LookState;
  who: (req: Request, res: Response) => { owner: boolean; open: boolean; look: LookState };
  requireOwner: (req: Request, res: Response, next: NextFunction) => void;
  secureCookies: (req: Request) => boolean;
  brandMarks: BrandMark[];
}

/** The directory of the one stylesheet, the one script and the scan scripts: public/ at the repository root. */
export const publicDir = path.join(import.meta.dirname, "..", "..", "public");
