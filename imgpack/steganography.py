import logging

import dotsi  # type: ignore

class Steganography():   
    """
    Steganography class and functions.

    Args:
        app_logger:     Name for logger
        app_settings:   Application settings object
    """
    def __init__(self, app_logger: logging.Logger, app_settings: dotsi.DotsiDict):

        self.log = app_logger
        self.settings = app_settings
        self.log.info("Steganography class constructor.")

        # State flags.
        self.img_to_proc = False
        self.img_proc_run = False
        self.img_done = True
        self.img_down = False
        self.loop_cnt = 0
    