#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DFIR-IRIS Folder Watcher Daemon
-------------------------------
Monitorea continuamente la carpeta inbox/ en busca de nuevos tickets PDF.
Procesa el archivo, clasifica el template, crea el caso en DFIR-IRIS,
y traslada el archivo a processed/ (o errors/ en caso de fallo).
"""

import time
import shutil
import logging
import argparse
from datetime import datetime
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import config
from parser import TicketParser, extract_text_from_pdf
from classifier import TemplateClassifier
from case_builder import CaseBuilder
from iris_client import IrisClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("iris_abuse_sync.watcher")


class TicketFileHandler(FileSystemEventHandler):
    def __init__(self, dry_run: bool = False):
        super().__init__()
        self.dry_run = dry_run
        self.client = IrisClient()
        self.clf = TemplateClassifier()
        self.processing = set()

    def on_created(self, event):
        if event.is_directory:
            return
        file_path = Path(event.src_path)
        self.process_file(file_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        file_path = Path(event.dest_path)
        self.process_file(file_path)

    def process_file(self, file_path: Path):
        # Only process .pdf and .txt
        if file_path.suffix.lower() not in (".pdf", ".txt"):
            return

        if file_path.name.startswith("."):
            return

        str_path = str(file_path)
        if str_path in self.processing:
            return

        self.processing.add(str_path)
        try:
            # Wait for file write to complete
            self._wait_for_file_stability(file_path)
            logger.info(f"Nuevo archivo detectado para procesamiento: {file_path.name}")

            # Extract text
            if file_path.suffix.lower() == ".pdf":
                raw_text = extract_text_from_pdf(file_path)
            else:
                raw_text = file_path.read_text(encoding="utf-8", errors="ignore")

            # Parse & classify
            parser = TicketParser(raw_text)
            data = parser.parse()
            classification = self.clf.classify(data)
            payload = CaseBuilder.build(data, classification)

            logger.info(
                f"Ticket {data['ticket_id']} clasificado como '{classification['template_name']}' "
                f"({classification['title_prefix']}) con {classification['confidence']*100:.1f}% de confianza."
            )

            # Create case in DFIR-IRIS
            res = self.client.create_case(payload, pdf_path=file_path, dry_run=self.dry_run)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest_name = f"{timestamp}_{file_path.name}"

            if res.get("success"):
                logger.info(f"✓ Caso creado exitosamente en IRIS: {res.get('case_name')} (ID: {res.get('case_id')}) -> {res.get('case_url')}")
                target_dest = config.PROCESSED_DIR / dest_name
                shutil.move(str(file_path), str(target_dest))

                # Save receipt metadata
                receipt_path = config.PROCESSED_DIR / f"{dest_name}.json"
                receipt_data = {
                    "processed_at": datetime.now().isoformat(),
                    "original_file": file_path.name,
                    "case_result": res,
                    "metadata": payload.get("metadata", {})
                }
                receipt_path.write_text(json.dumps(receipt_data, indent=2, ensure_ascii=False))
            else:
                logger.error(f"✗ Falló la creación del caso: {res.get('error')}")
                target_dest = config.ERRORS_DIR / dest_name
                shutil.move(str(file_path), str(target_dest))
                err_path = config.ERRORS_DIR / f"{dest_name}_error.txt"
                err_path.write_text(str(res.get("error", "Unknown error")))

        except Exception as e:
            logger.exception(f"Error procesando {file_path.name}: {e}")
            try:
                if file_path.exists():
                    target_dest = config.ERRORS_DIR / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file_path.name}"
                    shutil.move(str(file_path), str(target_dest))
            except Exception:
                pass
        finally:
            self.processing.discard(str_path)

    def _wait_for_file_stability(self, path: Path, max_retries: int = 10, interval: float = 0.5):
        """Ensures the file is fully copied/written before parsing."""
        last_size = -1
        for _ in range(max_retries):
            if not path.exists():
                return
            size = path.stat().st_size
            if size == last_size and size > 0:
                return
            last_size = size
            time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="Daemon de monitoreo de carpetas para tickets de abuso")
    parser.add_argument("--inbox", default=str(config.INBOX_DIR), help="Carpeta a monitorear")
    parser.add_argument("--dry-run", action="store_true", help="Modo simulación sin escribir en IRIS")
    args = parser.parse_args()

    watch_dir = Path(args.inbox)
    watch_dir.mkdir(parents=True, exist_ok=True)
    config.PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    config.ERRORS_DIR.mkdir(parents=True, exist_ok=True)

    event_handler = TicketFileHandler(dry_run=args.dry_run)
    observer = Observer()
    observer.schedule(event_handler, str(watch_dir), recursive=False)
    observer.start()

    logger.info(f"╔═══════════════════════════════════════════════════════════════╗")
    logger.info(f"║ Watcher activo monitoreando: {watch_dir}")
    logger.info(f"║ Modo: {'SIMULACIÓN (DRY-RUN)' if args.dry_run else 'PRODUCCIÓN / REAL'}")
    logger.info(f"║ IRIS Target: {config.IRIS_URL}")
    logger.info(f"╚═══════════════════════════════════════════════════════════════╝")
    logger.info("Presiona Ctrl+C para detener el servicio.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Deteniendo observador...")
        observer.stop()
    observer.join()


if __name__ == "__main__":
    import json
    main()
