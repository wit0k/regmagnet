import logging

from logging.handlers import WatchedFileHandler
from md.config import __logfile__

class Logger(object):

    def __init__(self):

        self.logger = logging.getLogger('regmagnet')
        log_handler = WatchedFileHandler(__logfile__)
        log_file_format = logging.Formatter(
            '%(levelname)s - THREAD-%(thread)d - %(asctime)s - %(filename)s - %(funcName)s - %(message)s')
        log_handler.setFormatter(log_file_format)
        self.logger.addHandler(log_handler)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.ERROR)
        log_console_format = logging.Formatter('%(message)s')
        console_handler.setFormatter(log_console_format)
        self.logger.addHandler(console_handler)
        self.logger.setLevel(logging.INFO)

    def getLogger(self, LoggerName):
        return logging.getLogger(LoggerName)

    def PrintCurrentLoggingLevel(self):
        #print(logging.getLogger().getEffectiveLevel())
        print(self.logger.getLogger().getEffectiveLevel())

    def SetLoggingLevel(self, LoggingLevel):

        if LoggingLevel in ['DEBUG', 'INFO', 'WARNING']:
            #logging.getLogger().setLevel(logging.getLevelName(LoggingLevel))
            self.logger.setLevel(logging.getLevelName(LoggingLevel))
        else:
            logging.error('Unsupported logging level: %s' % LoggingLevel)


