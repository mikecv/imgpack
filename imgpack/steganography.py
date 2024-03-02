import logging
import os

import dotsi  # type: ignore

from PIL import Image

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
        self.img_proc_running = False
        self.reset_proc = False
        self.reset_req = False
        self.stay_alive = True

        # Initialise image / steganography settings.
        self.initPicSettings()

    """
    Perform steganography image parameters.
    """
    def initPicSettings(self):

        # Initialise image coding details
        self.image_file = ""
        self.pic_coded = False
        self.pic_code_type = self.settings.steg.CODETYPE_NONE
        self.pic_password = False
        self.password = ""
        self.pic_code_name_len = 0

        # Initialise image file read parameters.
        self.row = 0
        self.col = 0
        self.plane = 0
        self.bit = 0
        self.bytes_read = 0
        self.bytes_written = 0
        self.code_bytes = []

        # Initialise parameters for embedded file.
        self.embedded_file_path = ""
        self.embedded_file_name = ""
        self.embedded_file_size = 0
        self.toEmbed_file_path = ""
        self.toEmbed_file_size = 0

        # Initialise approximate embedding capacity of image.
        self.capacity = 0

    """
    Load image file for scanning and processing.

    Args:
        img_file:       Name (inc. path) of file to load.
    """
    def load_image(self, img_file: str) -> None:
        self.image_file = img_file
        self.log.debug(f"Loading image file for processing: {self.image_file}")

        # Open the image fillow using Pillow library.
        self.image = Image.open(self.image_file)

        # Get image size.
        self.width, self.height = self.image.size
        self.log.debug(f"Image loaded with width: {self.width}, height:{self.height}")

        # Get image format.
        # Only support PNG images.
        self.can_code = False
        self.image_format = self.image.format
        self.log.debug(f"Image loaded with format: {self.image_format}")
        if self.image_format == "PNG": self.can_code = True
        self.log.debug(f"Image suitable for coding: {self.can_code}")
    
        # Only support 3 colour planes.
        # If transparency A then still only 3 planes.
        self.col_planes = 0
        self.image_mode = self.image.mode
        self.log.debug(f"Image loaded with mode: {self.image_mode}")
        if self.image_mode in ['RGB', 'RGBA']:
            self.col_planes = 3
        self.log.debug(f"Image colour planes: {self.col_planes}")

        # Calculate space available for coding.
        self.picBytes = self.width * self.height * self.col_planes
        self.log.debug(f'Absolute maximimum space for embedding (Bytes): {self.picBytes}')

        # Check if image file is encoded.
        self.checkForCode()

        # If is a picCoded image, then need to get type and associated data.
        if self.pic_coded:
            self.getPicCodedData()

    """
    Check if image has necessary preamble
    that indicates that it has been encoded.
    """
    def checkForCode(self):
        self.log.info("Checking image for preamble...")

        # Check if file even large enough to hold a code.
        self.fileSize = os.path.getsize(self.image_file)
        if self.fileSize < (len(self.settings.steg.PROGCODE) + self.settings.steg.LENBYTES):
            self.log.warning(f'File too small to be encoded: {self.fileSize}')
        else:
            # Read from image file to see if it contains the header code.
            bytes_to_read = len(self.settings.steg.PROGCODE)
            self.readDataFromImage(bytes_to_read)
            self.log.debug(f'Expected bytes: {bytes_to_read}; bytes read: {self.bytes_read}')
            # Check if we read the expected number of bytes.
            if (self.bytes_read != bytes_to_read):
                self.log.error(f'Expected bytes: {bytes_to_read}; bytes read: {self.bytes_read}')
            else:
                # Check if the code matches the expected code.
                prog_code = ""
                try:
                    prog_code = self.code_bytes.decode('utf-8')
                except:
                    self.log.debug("Failed to read header code from image.")

                if prog_code == self.settings.steg.PROGCODE:
                    # Yes! We have a picCoded image.
                    self.log.info("Image file contains header code.")
                    self.pic_coded = True
                    # Check if the embedded file has password protection.
                    bytes_to_read = self.settings.steg.PASSWDYNBYTES
                    self.readDataFromImage(bytes_to_read)
                    # Check if we read the expected number of bytes.
                    if (self.bytes_read != bytes_to_read):
                        self.log.error(f'Expected bytes: {bytes_to_read}; bytes read: {self.bytes_read}')
                    else:
                        self.pic_password = bool(int(self.code_bytes.decode('utf-8')))
                        self.log.info(f'Image file has password protection: {self.pic_password}')
                        # Get the length of the password.
                        bytes_to_read = self.settings.steg.PASSWDLENBYTES
                        self.readDataFromImage(bytes_to_read)
                        # Check if we read the expected number of bytes.
                        if (self.bytes_read != bytes_to_read):
                            self.log.error(f'Expected bytes: {bytes_to_read}; bytes read: {self.bytes_read}')
                        else:
                            self.pic_pw_len = int(self.code_bytes.decode('utf-8'))
                            self.log.debug(f'Password length: {self.pic_pw_len}')
                            # Get the password.
                            bytes_to_read = self.pic_pw_len
                            self.readDataFromImage(bytes_to_read)
                            # Check if we read the expected number of bytes.
                            if (self.bytes_read != bytes_to_read):
                                self.log.error(f'Expected bytes: {bytes_to_read}; bytes read: {self.bytes_read}')
                            else:
                                self.password = self.code_bytes.decode('utf-8')
                                self.log.debug("Image password (or not) read.")
                else:
                    self.log.debug("Image file did not contain a valid header code.")

    """
    Read picCoded data from image.
    """
    def getPicCodedData(self):

        # Read the data type field.
        bytes_to_read = self.settings.steg.CODETYPEBYTES
        self.readDataFromImage(bytes_to_read)
        # Check if we read the expected number of bytes.
        if (self.bytes_read != bytes_to_read):
            self.log.error(f'Expected bytes: {bytes_to_read}; bytes read: {self.bytes_read}')
        else:
            self.pic_code_type = int(self.code_bytes.decode('utf-8'))
            self.log.info(f'Image file has embedded data of type: {self.pic_code_type}')

            # Get data based on embedded data type:
             # Text conversation.
            if self.pic_code_type == self.settings.steg.CODETYPE_FILE:
                # Image has an embedded file.
                # Read the length of the filename.
                bytes_to_read = self.settings.steg.NAMELENBYTES
                self.readDataFromImage(bytes_to_read)
                # Check if we read the expected number of bytes.
                if (self.bytes_read != bytes_to_read):
                    self.log.error(f'Expected bytes: {bytes_to_read}; bytes read: {self.bytes_read}')
                else:
                    self.pic_code_name_len = int(self.code_bytes.decode('utf-8'))
                    self.log.info(f'Image file has embedded file with filename length: {self.pic_code_name_len}')
                    # Read the filename.
                    bytes_to_read = self.pic_code_name_len
                    self.readDataFromImage(bytes_to_read)
                    # Check if we read the expected number of bytes.
                    if (self.bytes_read != bytes_to_read):
                        self.log.error(f'Expected bytes: {bytes_to_read}; bytes read: {self.bytes_read}')
                    else:
                        self.embedded_file_path = self.code_bytes.decode('utf-8')
                        self.log.info(f'Embedded file full path: {self.embedded_file_path}')
                        head, self.embeddedFileName = os.path.split(self.embedded_file_path)
                        self.log.info(f'Embedded file has filename: {self.embeddedFileName}')
                        # Now that we have the filename we can read the file size.
                        bytes_to_read = self.settings.steg.LENBYTES
                        self.readDataFromImage(bytes_to_read)
                        # Check if we read the expected number of bytes.
                        if (self.bytes_read != bytes_to_read):
                            self.log.error(f'Expected bytes: {bytes_to_read}; bytes read: {self.bytes_read}')
            else:
                # Unsupported embedded data type.
                self.log.error("Unsupported coded data type.")

    """
    Read buffer of data from image file.
    Continue reading from where we left off.
    """
    def readDataFromImage(self, bytes_to_read):
        # Initialise loop counters counters.
        bytes_read = 0
        row_cnt = self.row
        col_cnt = self.col
        col_plane = self.plane
        bits_read = self.bit

        # Initialise array to hold read data.
        self.code_bytes = bytearray()

        # Intialise colour bit mask.
        mask = 1 << bits_read

        while bytes_read < bytes_to_read:
            code_data = 0

            # Extract a byte worth of data.
            for bit_cnt in range(0, 8):
                #col_part = QtGui.QColor(self.image.pixel(col_cnt, row_cnt)).getRgb()[col_plane]
                col_part = self.image.getpixel((col_cnt, row_cnt))[col_plane]
                byte_bit = col_part & mask
                byte_bit = byte_bit >> bits_read
                code_data = code_data << 1
                code_data = code_data | byte_bit                 
    
                # Point to next column.
                col_cnt += 1
                if col_cnt == self.width:
                    col_cnt = 0
                    row_cnt += 1
                    # If we have reached the end of the image then go
                    # back to the top and go to the text bit.
                    if row_cnt == self.height:
                        row_cnt = 0
                        col_plane += 1
                        if col_plane == self.col_planes:
                            col_plane = 0
                            # Used all colour planes so move to next bit.
                            bits_read += 1
                            mask = mask <<  1
   
            # Append the character to the code byte array.
            self.code_bytes.append(code_data)
    
            # Increment characters read counter.
            bytes_read += 1

        # Update loop counters for next time.
        self.row = row_cnt
        self.col = col_cnt
        self.plane = col_plane
        self.bit = bits_read
        self.bytes_read = bytes_read
