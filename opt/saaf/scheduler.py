#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — scheduler.py
# Ciclo automatico (diario o semanal, configurable desde el Dashboard)
# usando APScheduler. Genera el reporte diario consolidado y registra
# logs del ciclo.
# Ruta: /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/scheduler.py
# =============================================================

import logging
import sys
import os
import signal
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

LOG_DIR = Path("/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "scheduler.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("scheduler")

sys.path.insert(0, "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf")
sys.path.insert(0, "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/scripts/python")

# =============================================================
# Importaciones con manejo de errores claro
# =============================================================
try:
    from apscheduler.schedulers.blocking import BlockingScheduler
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.triggers.interval import IntervalTrigger
    from apscheduler.triggers.date import DateTrigger
    from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR
except ImportError:
    logger.error("APScheduler no instalado. Correr:")
    logger.error(
        "  /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/pip install 'apscheduler==3.10.4'"
    )
    sys.exit(1)

try:
    from orchestrator import run_cycle
except ImportError as e:
    logger.error("No se pudo importar orchestrator: %s", e)
    sys.exit(1)

try:
    from database import (
        init_db,
        start_cycle_log,
        finish_cycle_log,
        get_cycle_logs,
        add_report,
        get_dashboard_summary,
        get_schedule_config,
        get_once_run,
        clear_once_run,
        reap_stale_audits,
        COLOMBIA_TZ,
    )
    from audit_state import classify_result
except ImportError as e:
    logger.error("No se pudo importar database/audit_state: %s", e)
    sys.exit(1)

try:
    from alerts import send_daily_report
except ImportError as e:
    logger.error("No se pudo importar alerts: %s", e)
    sys.exit(1)


# =============================================================
# Ciclo principal instrumentado
# =============================================================


# Evita que dos disparos (p. ej. el ciclo diario y una ejecucion unica)
# corran a la vez sobre los mismos sitios.
_cycle_lock = threading.Lock()


def run_scheduled_cycle():
    """
    Ejecuta el ciclo completo de auditoria para todos los sitios.
    Registra inicio/fin en cycle_logs y envia el reporte diario.
    La llama APScheduler segun la frecuencia configurada (diaria/semanal)
    o por una ejecucion unica programada desde el Dashboard.
    """
    if not _cycle_lock.acquire(blocking=False):
        logger.warning("Ya hay un ciclo en curso — se omite este disparo")
        return
    try:
        _run_scheduled_cycle_locked()
    finally:
        _cycle_lock.release()


def _run_scheduled_cycle_locked():
    started_at = datetime.now(timezone.utc)
    started_at_co = started_at.astimezone(COLOMBIA_TZ)
    logger.info("=" * 60)
    logger.info(
        "Inicio de ciclo programado: %s (%s UTC)",
        started_at_co.strftime("%Y-%m-%d %H:%M:%S"),
        started_at.strftime("%Y-%m-%d %H:%M:%S"),
    )
    logger.info("=" * 60)

    # Registrar inicio del ciclo en BD
    log_id = start_cycle_log()
    logger.info("cycle_log_id = %d", log_id)

    summary = {
        "sites_total": 0,
        "sites_ok": 0,
        "sites_issues": 0,
        "sites_down": 0,
        "sites_error": 0,
        "sites_cancelled": 0,
        "duration_sec": 0,
    }
    site_results = []
    
    try:
        # Ejecutar el ciclo — run_cycle devuelve resultados por sitio
        results = run_cycle(cycle_log_id=log_id, scheduled=True)

        if not results:
            # Todas las campañas tienen programacion propia o auditoria automatica
            # desactivada (paquete enhancements): no es un error, solo no hay nada
            # que hacer en el ciclo general.
            try:
                from enhancements import all_sites_self_scheduled

                if all_sites_self_scheduled():
                    logger.info("Ciclo general sin campañas: todas tienen programación propia o auditoría automática desactivada")
                    summary['duration_sec'] = (datetime.now(timezone.utc) - started_at).total_seconds()
                    finish_cycle_log(log_id, status='ok', sites_total=0)
                    return
            except Exception:
                pass
            # Sin sitios activos (o ciclo abortado): NO es un ciclo exitoso
            # ni hay nada que reportar por email.
            msg = "Sin resultados: no hay sitios activos para auditar"
            logger.warning(msg)
            summary['duration_sec'] = (datetime.now(timezone.utc) - started_at).total_seconds()
            finish_cycle_log(log_id, status='error', error_msg=msg)
            return

        for r in results:
            site_results.append(r)
            summary['sites_total'] += 1
            # is_up False = sitio caido. is_up None = no se pudo auditar
            # (error interno) y NO debe contarse como caido.
            # classify_result() entiende los estados nuevos (COMPLETED, FAILED...)
            kind = classify_result(r)
            if kind == 'down':
                summary['sites_down'] += 1
            elif kind == 'ok':
                summary['sites_ok'] += 1
            elif kind == 'issues':
                summary['sites_issues'] += 1
            elif kind == 'cancelled':
                summary['sites_cancelled'] += 1
            else:
                summary['sites_error'] += 1
        
        finished_at = datetime.now(timezone.utc)
        duration = (finished_at - started_at).total_seconds()
        summary['duration_sec'] = duration
        
        # Cerrar el log del ciclo. Antes siempre quedaba 'ok' aunque hubiera
        # auditorias FAILED: ahora refleja el resultado real.
        notes = []
        if summary['sites_error']:
            notes.append(f"{summary['sites_error']} auditoría(s) fallaron")
        if summary['sites_cancelled']:
            notes.append(f"{summary['sites_cancelled']} cancelada(s) manualmente")
        finish_cycle_log(
            log_id,
            status='error' if notes else 'ok',
            sites_total=summary['sites_total'],
            sites_ok=summary['sites_ok'],
            sites_issues=summary['sites_issues'],
            sites_down=summary['sites_down'],
            sites_error=summary['sites_error'],
            error_msg='; '.join(notes) or None,
        )
        
        logger.info("Ciclo completado en %.1f segundos", duration)
        logger.info("  Total   : %d", summary['sites_total'])
        logger.info("  OK      : %d", summary['sites_ok'])
        logger.info("  Issues  : %d", summary['sites_issues'])
        logger.info("  Caidos  : %d", summary['sites_down'])
        logger.info("  Errores : %d", summary['sites_error'])
        
        # Enviar reporte diario por email
        _send_report(summary, site_results)
        
        # Guardar referencia del reporte en BD
        date_str = started_at.strftime('%Y-%m-%d')
        report_path = str(LOG_DIR / f"report_{date_str}.txt")
        _save_report_file(report_path, summary, site_results)
        add_report('daily', report_path, summary=str(summary))
    
    except Exception as e:
        logger.error("Error critico en ciclo: %s", e, exc_info=True)
        finished_at = datetime.now(timezone.utc)
        summary['duration_sec'] = (finished_at - started_at).total_seconds()
        finish_cycle_log(log_id, status='error', error_msg=str(e),
                         sites_total=summary['sites_total'])

def _send_report(summary: dict, site_results: list):
    """Envia el reporte diario por email si hay destinatarios."""
    try:
        sent = send_daily_report(summary, site_results)
        if sent == 0:
            logger.info("Reporte diario no enviado (sin destinatarios o email deshabilitado)")
    except Exception as e:
        logger.warning("Error enviando reporte diario: %s", e)

def _save_report_file(path: str, summary: dict, site_results: list):
    """Guarda el reporte diario como archivo de texto en /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/logs/."""
    try:
        now = datetime.now(timezone.utc).astimezone(COLOMBIA_TZ).strftime('%Y-%m-%d %H:%M (Colombia)')
        lines = [
            f"SAAF Pro — Reporte diario {now}",
            "=" * 60,
            f"Duracion  : {summary.get('duration_sec', 0):.0f}s",
            f"Total     : {summary.get('sites_total', 0)}",
            f"OK        : {summary.get('sites_ok', 0)}",
            f"Issues    : {summary.get('sites_issues', 0)}",
            f"Caidos    : {summary.get('sites_down', 0)}",
            f"Errores   : {summary.get('sites_error', 0)}",
            "",
        ]
        for r in site_results:
            site = r.get('site', {})
            status = r.get('status', 'unknown')
            sev = r.get('severity_max', '')
            sev_str = f" [{sev}]" if sev else ""
            lines.append(f"  {site.get('name', '')} — {status.upper()}{sev_str}")
        Path(path).write_text('\n'.join(lines), encoding='utf-8')
        logger.info("Reporte guardado: %s", path)
    except Exception as e:
        logger.warning("Error guardando reporte en archivo: %s", e)
        
# =============================================================
# Listener de eventos del scheduler
# =============================================================

def _audit_watchdog():
    """
    Vigilante de auditorias: cada pocos minutos cierra como FAILED/CANCELLED las
    que quedaron PENDING/RUNNING pero ya no se ejecutan (proceso muerto, hilo
    colgado, reinicio del servicio...). Corre en su propio hilo del scheduler,
    asi funciona incluso mientras un ciclo largo esta en curso.
    """
    try:
        for c in reap_stale_audits():
            logger.warning("Vigilante: auditoria %s -> %s (%s)", c["id"], c["status"], c["reason"])
    except Exception as e:
        logger.warning("Vigilante de auditorias fallo: %s", e)


def _job_listener(event):
    """Loguea exito o fallo de cada ejecucion del job."""
    if event.exception:
        logger.error("Job fallo con excepcion: %s", event.exception)
    else:
        logger.info("Job completado exitosamente")


# =============================================================
# Frecuencia configurable (diaria/semanal) — leida desde la BD
# =============================================================

_last_schedule_signature = None
_last_once_signature = None
ONCE_JOB_ID = 'once_audit'


def _build_trigger_from_config(cfg: dict) -> CronTrigger:
    """
    Construye el CronTrigger de APScheduler a partir de la config de frecuencia.
 
    IMPORTANTE: se pasa timezone=COLOMBIA_TZ explicitamente. APScheduler
    NO hereda automaticamente el timezone del BlockingScheduler hacia el
    trigger si este no lo especifica — si se omite aqui, el trigger cae
    a UTC aunque el scheduler este configurado en 'America/Bogota', y el
    ciclo terminaria ejecutandose 5 horas mas tarde de lo esperado.
    """
    hour = cfg.get('hour', 8)
    minute = cfg.get('minute', 0)
    if cfg.get('frequency') == 'weekly':
        weekday = cfg.get('weekday', 'mon')
        return CronTrigger(day_of_week=weekday, hour=hour, minute=minute, timezone=COLOMBIA_TZ)
    return CronTrigger(hour=hour, minute=minute, timezone=COLOMBIA_TZ)


def _schedule_signature(cfg: dict) -> tuple:
    """Tupla comparable para detectar si la configuracion de frecuencia cambio."""
    return (
        cfg.get('frequency', 'daily'),
        cfg.get('hour', 8),
        cfg.get('minute', 0),
        cfg.get('weekday', 'mon') if cfg.get('frequency') == 'weekly' else None,
    )
    

def _describe_schedule(cfg: dict) -> str:
    if cfg.get('frequency') == 'weekly':
        return (
            f"Semanal — cada {cfg.get('weekday', 'mon')} "
            f"a las {cfg.get('hour', 8):02d}:{cfg.get('minute', 0):02d} (hora de Colombia)"
        )
    return f"Diaria — todos los dias a las {cfg.get('hour', 8):02d}:{cfg.get('minute', 0):02d} (hora de Colombia)"


def _run_once_cycle():
    """
    Ejecucion unica: borra la programacion ANTES de correr (asi un reinicio
    del servicio no la repite) y luego ejecuta el ciclo normal.
    """
    global _last_once_signature
    try:
        clear_once_run()
        _last_once_signature = None
    except Exception as e:
        logger.warning("No se pudo limpiar la ejecucion unica: %s", e)
    logger.info("Disparando ejecucion unica programada desde el Dashboard")
    run_scheduled_cycle()


def _check_and_apply_once(scheduler):
    """
    Lee la ejecucion unica pendiente (Dashboard -> 🕐 Frecuencia) y la
    programa como job 'once_audit'. Si se cancelo, elimina el job. Si la
    fecha ya paso por mas del margen de gracia (1 h), la descarta.
    """
    global _last_once_signature
    try:
        once = get_once_run()
    except Exception as e:
        logger.warning("No se pudo leer once_run desde la BD: %s", e)
        return

    sig = (once['date'], once['hour'], once['minute']) if once else None
    if sig == _last_once_signature:
        return  # sin cambios

    try:
        if scheduler.get_job(ONCE_JOB_ID):
            scheduler.remove_job(ONCE_JOB_ID)

        if once is None:
            logger.info("Ejecucion unica cancelada / sin programar")
            _last_once_signature = None
            return

        run_at = datetime.strptime(once['date'], '%Y-%m-%d').replace(
            hour=once['hour'], minute=once['minute'], tzinfo=COLOMBIA_TZ
        )
        now = datetime.now(COLOMBIA_TZ)
        if run_at < now - timedelta(hours=1):
            logger.warning(
                "Ejecucion unica %s ya paso (hace mas de 1 h) — se descarta",
                run_at.strftime('%Y-%m-%d %H:%M'),
            )
            clear_once_run()
            _last_once_signature = None
            return

        scheduler.add_job(
            _run_once_cycle,
            trigger=DateTrigger(run_date=run_at, timezone=COLOMBIA_TZ),
            id=ONCE_JOB_ID,
            name='SAAF Pro ejecucion unica',
            max_instances=1,
            misfire_grace_time=3600,
            replace_existing=True,
        )
        _last_once_signature = sig
        logger.info(
            "Ejecucion unica programada para %s (hora de Colombia)",
            run_at.strftime('%Y-%m-%d %H:%M'),
        )
    except Exception as e:
        logger.error("Error programando ejecucion unica: %s", e, exc_info=True)


def _check_and_apply_schedule(scheduler):
    """
    Job periodico (cada 5 min) que relee desde la BD la configuracion del
    Dashboard (boton "🕐 Frecuencia"): la frecuencia diaria/semanal —
    reprograma 'daily_audit' en caliente si cambio — y la ejecucion unica.
    Esto evita reiniciar el servicio systemd al cambiar la configuracion.
    """
    _check_and_apply_once(scheduler)
    _apply_recurring_schedule(scheduler)


def _apply_recurring_schedule(scheduler):
    global _last_schedule_signature
    try:
        cfg = get_schedule_config()
    except Exception as e:
        logger.warning("No se pudo leer schedule_config desde la BD: %s", e)
        return
 
    sig = _schedule_signature(cfg)
    if sig == _last_schedule_signature:
        return  # sin cambios desde la ultima revision
 
    try:
        new_trigger = _build_trigger_from_config(cfg)
        scheduler.reschedule_job('daily_audit', trigger=new_trigger)
        _last_schedule_signature = sig
        logger.info(
            "Frecuencia del ciclo actualizada desde el Dashboard -> %s",
            _describe_schedule(cfg),
        )
    except Exception as e:
        logger.error("Error reprogramando 'daily_audit': %s", e, exc_info=True)


# =============================================================
# Iniciar el scheduler
# =============================================================

def start(hour: int = None, minute: int = None, run_now: bool = False):
    """
    Inicia el scheduler bloqueante.
 
    La frecuencia (diaria o semanal), hora y dia se leen normalmente
    desde la configuracion guardada en la BD (tabla app_settings) —
    la misma que se edita con el boton "🕐 Frecuencia" del Dashboard.
    Un job interno ('schedule_watcher') revisa esa configuracion cada
    5 minutos y reprograma el ciclo automaticamente si cambio, sin
    necesidad de reiniciar este proceso ni el servicio systemd.
 
    Args:
        hour:    Si se especifica (junto con minute), fuerza un horario
                 diario puntual SOLO para el arranque de este proceso
                 (uso manual/pruebas via --hour/--minute). El watcher
                 puede sobreescribirlo en su siguiente revision si hay
                 una configuracion distinta guardada desde el Dashboard.
        minute:  Ver 'hour'.
        run_now: Si True, ejecuta un ciclo inmediatamente al arrancar.
    """
    global _last_schedule_signature
    
    # Inicializar BD
    init_db()
    # Limpiar de inmediato auditorias que quedaron colgadas antes del reinicio
    _audit_watchdog()
    # systemd stop -> SIGTERM: convertirlo en SystemExit para cerrar estados limpiamente
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(143))
    
    if hour is not None or minute is not None:
        # Override manual via CLI (--hour/--minute).
        # SAAF_SCHEDULE_HOUR/MINUTE se mantienen como fallback legado.
        env_hour = os.environ.get('SAAF_SCHEDULE_HOUR')
        env_minute = os.environ.get('SAAF_SCHEDULE_MINUTE')
        final_hour = hour if hour is not None else (int(env_hour) if env_hour is not None else 8)
        final_minute = minute if minute is not None else (int(env_minute) if env_minute is not None else 0)
        cfg = {'frequency': 'daily', 'hour': final_hour, 'minute': final_minute, 'weekday': 'mon'}
        logger.info("Usando horario forzado por linea de comandos: %02d:%02d (hora de Colombia)", final_hour, final_minute)
    else:
        # Fuente de verdad: configuracion guardada desde el Dashboard.
        cfg = get_schedule_config()
        # Compatibilidad con instalaciones previas: si NUNCA se guardo
        # configuracion desde el Dashboard pero SI existen las variables
        # de entorno legado, se respetan (comportamiento previo).
        from database import get_setting
        if get_setting('schedule_config') is None:
            env_hour = os.environ.get('SAAF_SCHEDULE_HOUR')
            env_minute = os.environ.get('SAAF_SCHEDULE_MINUTE')
            if env_hour is not None:
                cfg['hour'] = int(env_hour)
            if env_minute is not None:
                cfg['minute'] = int(env_minute)
    
    trigger = _build_trigger_from_config(cfg)
    _last_schedule_signature = _schedule_signature(cfg)
                
    # El BlockingScheduler tambien se configura en hora de Colombia por
    # consistencia (afecta el calculo de misfire_grace_time y el reloj
    # interno que usa APScheduler); el timezone real que importa para el
    # disparo correcto del cron es el que se pasa a CronTrigger arriba.
    scheduler = BlockingScheduler(timezone=COLOMBIA_TZ)
    scheduler.add_listener(_job_listener, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR)
    
    # Job del ciclo de auditoria — diario o semanal segun configuracion
    scheduler.add_job(
        run_scheduled_cycle,
        trigger=trigger,
        id='daily_audit',
        name='SAAF Pro ciclo de auditoria',
        max_instances=1, # Evita solapamiento si el ciclo tarda mas de 24h
        misfire_grace_time=3600, # Margen de 1h si el sistema estuvo apagado
        replace_existing=True,
    )
    
    # Job "watcher" — revisa cada 5 min si la frecuencia cambio desde el
    # Dashboard y reprograma 'daily_audit' en caliente si es necesario.
    scheduler.add_job(
        _check_and_apply_schedule,
        trigger=IntervalTrigger(minutes=5),
        id='schedule_watcher',
        name='SAAF Pro — watcher de frecuencia',
        args=[scheduler],
        max_instances=1,
        replace_existing=True,
    )
    
    scheduler.add_job(
        _audit_watchdog,
        trigger=IntervalTrigger(minutes=2),
        id='audit_watchdog',
        name='SAAF Pro — vigilante de auditorias',
        max_instances=1,
        replace_existing=True,
    )
    
    logger.info("Scheduler iniciado — %s", _describe_schedule(cfg))

    # Ejecucion unica pendiente (si la hay) — se programa desde el arranque
    _check_and_apply_once(scheduler)
    
    # Programacion por campania y reportes con calendario propio (paquete
    # enhancements). Hilo propio: no agrega jobs ni lineas a la consola.
    try:
        from enhancements import start_ticker

        start_ticker()
    except Exception as e:
        logger.warning("Programación por campaña no disponible: %s", e)
    
    if run_now:
        logger.info("Ejecutando ciclo inicial inmediato (--run-now)")
        run_scheduled_cycle()
    
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Scheduler detenido por el usuario")
        scheduler.shutdown(wait=False)
        

# =============================================================
# Entrypoint
# =============================================================

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='SAAF Pro — Scheduler')
    parser.add_argument('--hour', type=int, default=None,
                        help='Fuerza un horario diario puntual en hora de Colombia (0-23), ignorando la '
                             'frecuencia guardada desde el Dashboard para el arranque inicial')
    parser.add_argument('--minute', type=int, default=None,
                        help='Minuto del horario forzado (0-59, default: 0). Ver --hour')
    parser.add_argument('--run-now', action='store_true',
                        help='Ejecutar un ciclo inmediatamente al arrancar')
    parser.add_argument('--once', action='store_true',
                        help='Ejecutar un solo ciclo ahora sin iniciar el scheduler')
    args = parser.parse_args()
    
    if args.once:
        logger.info("Modo --once: ejecutando ciclo unico")
        init_db()
        run_scheduled_cycle()
    else:
        start(hour=args.hour, minute=args.minute, run_now=args.run_now)