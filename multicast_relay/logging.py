import sys

import logging.handlers
from typing import Any


class Logger:
    def __init__(self, foreground: bool, logfile: str, verbose: bool):
        self.verbose = verbose

        logger = logging.getLogger()
        syslog_handler = logging.handlers.SysLogHandler()
        syslog_handler.setFormatter(
            logging.Formatter(
                fmt="%(name)s[%(process)d] %(levelname)s: %(message)s"
            )
        )
        logger.addHandler(syslog_handler)

        if foreground:
            stream_handler = logging.StreamHandler(sys.stdout)
            stream_handler.setFormatter(
                logging.Formatter(
                    fmt="%(asctime)s %(name)s %(levelname)s: %(message)s",
                    datefmt="%b-%d %H:%M:%S",
                )
            )
            logger.addHandler(stream_handler)

        if logfile:
            file_handler = logging.FileHandler(logfile)
            file_handler.setFormatter(
                logging.Formatter(
                    fmt="%(asctime)s %(name)s %(levelname)s: %(message)s",
                    datefmt="%b-%d %H:%M:%S",
                )
            )
            logger.addHandler(file_handler)

            if verbose:
                logger.setLevel(logging.INFO)
            else:
                logger.setLevel(logging.WARN)

    def info(self, *args: Any, **kwargs: Any):
        logging.getLogger(__file__).info(*args, **kwargs)
        if self.verbose:
            print(args, kwargs)

    def warning(self, *args: Any, **kwargs: Any):
        logging.getLogger(__file__).warning(*args, **kwargs)
        print(args, kwargs)
