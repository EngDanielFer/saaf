-- Esquema de la VERSION ANTERIOR (CRITICO/ALTO/MEDIO/BAJO; running/ok/issues/error),
-- tal como estaba en produccion antes de la migracion v2. Solo para tests.
CREATE TABLE sites (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, url TEXT NOT NULL UNIQUE, sitemap_url TEXT,
  niche TEXT NOT NULL DEFAULT 'general', priority TEXT NOT NULL DEFAULT 'normal' CHECK(priority IN ('high','normal','low')),
  active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE cycle_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL, finished_at TEXT,
  status TEXT NOT NULL DEFAULT 'running' CHECK(status IN ('running','ok','error')), sites_total INTEGER DEFAULT 0, sites_ok INTEGER DEFAULT 0,
  sites_issues INTEGER DEFAULT 0, sites_down INTEGER DEFAULT 0, sites_error INTEGER DEFAULT 0, error_msg TEXT);
CREATE TABLE audits (id INTEGER PRIMARY KEY AUTOINCREMENT, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  started_at TEXT NOT NULL, finished_at TEXT, crawl_method TEXT CHECK(crawl_method IN ('sitemap','crawl','none')), urls_analyzed INTEGER DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'running' CHECK(status In ('running','ok','issues','error')),
  severity_max TEXT CHECK(severity_max IN ('CRITICO','ALTO','MEDIO','BAJO') OR severity_max IS NULL), error_msg TEXT,
  cycle_log_id INTEGER REFERENCES cycle_logs(id));
CREATE TABLE threats (id INTEGER PRIMARY KEY AUTOINCREMENT, audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE, detected_at TEXT NOT NULL DEFAULT (datetime('now')),
  threat_type TEXT NOT NULL, severity TEXT NOT NULL CHECK (severity in ('CRITICO','ALTO','MEDIO','BAJO')), description TEXT NOT NULL,
  code_snippet TEXT, url_found TEXT, resolved INTEGER NOT NULL DEFAULT 0, resolved_at TEXT, is_new INTEGER NOT NULL DEFAULT 1,
  ignored INTEGER NOT NULL DEFAULT 0, ignored_at TEXT);
CREATE TABLE uptime (id INTEGER PRIMARY KEY AUTOINCREMENT, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  checked_at TEXT NOT NULL DEFAULT (datetime('now')), is_up INTEGER NOT NULL, status_code INTEGER, response_time_ms INTEGER, error_msg TEXT);
CREATE TABLE reports (id INTEGER PRIMARY KEY AUTOINCREMENT, generated_at TEXT NOT NULL DEFAULT (datetime('now')),
  report_type TEXT NOT NULL CHECK(report_type IN ('daily','site')), site_id INTEGER REFERENCES sites(id) ON DELETE SET NULL, file_path TEXT NOT NULL, summary TEXT);
CREATE TABLE spam_domains (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL UNIQUE, added_at TEXT NOT NULL DEFAULT (datetime('now')), added_by TEXT DEFAULT 'manual');
CREATE INDEX idx_audits_site ON audits(site_id, started_at DESC);
CREATE INDEX idx_threats_site ON threats(site_id, detected_at DESC);
INSERT INTO sites (id,name,url) VALUES (1,'Sitio','https://sitio.com');
INSERT INTO audits (id,site_id,started_at,finished_at,status,severity_max) VALUES
  (1,1,'2026-01-01T10:00:00+00:00','2026-01-01T10:05:00+00:00','issues','ALTO'),
  (2,1,'2026-01-02T10:00:00+00:00','2026-01-02T10:05:00+00:00','ok',NULL),
  (3,1,'2026-01-03T10:00:00+00:00',NULL,'running',NULL),
  (4,1,'2026-01-04T10:00:00+00:00','2026-01-04T10:01:00+00:00','error',NULL);
INSERT INTO threats (audit_id,site_id,threat_type,severity,description,url_found) VALUES
  (1,1,'external_script','MEDIO',  'Script externo de dominio unknown: x.com (src=''https://x.com/a.js'')','https://sitio.com/'),
  (1,1,'hidden_iframe','ALTO',     'Iframe oculto detectado: src=''https://www.google.com/recaptcha/api2/aframe''','https://sitio.com/'),
  (1,1,'hidden_spam_link','CRITICO','Link externo oculto: dominio=''m.me'' href=''https://m.me/pagina'' texto=''chat''','https://sitio.com/'),
  (1,1,'external_script','MEDIO',  'Script externo de dominio unknown: y.com (src=''https://y.com/b.js'')','https://sitio.com/x'),
  (1,1,'obfuscated_js','BAJO',     'JavaScript ofuscado: eval(','https://sitio.com/');