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
    def load_New_Image(self, img_file: str) -> None:
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

        # Check approximate embedding capacity of image.
        self.calc_Embedding_Capacity()

        # Check if image file is encoded.
        self.check_For_Code()

        # If is a picCoded image, then need to get type and associated data.
        if self.pic_coded:
            self.get_Pic_Coded_Data()

    """
    Check embedding capacity of image.
    Embedding capacity is approximate as preamble is not fixed.
    """
    def calc_Embedding_Capacity(self):
        self.log.info(f'Calculating image embedding capacity for embed ratio : {self.settings.code.MAX_EMBED_RATIO}')

        # Embedding capacity pixels * colours * colourBits * MaxEmbedRatio / 8 bitsPerByte
        self.capacity = int(self.picWidth * self.picHeight * 3 * self.settings.code.MAX_EMBED_RATIO)
        self.log.debug(f'Approximate embedding capacity, including preamble (Bytes) : {self.capacity}')

    """
    Check if image has necessary preamble
    that indicates that it has been encoded.
    Essential checks to see if the image is a normal image,
    or includes one or more embedded files.
    """
    def check_For_Code(self):
        self.log.info("Checking image for code preamble...")

        # Check if file even large enough to hold a code.
        self.fileSize = os.path.getsize(self.image_file)
        if self.fileSize < (len(self.settings.steg.PROGCODE) + self.settings.steg.LENBYTES):
            self.log.warning(f'File too small to be encoded: {self.fileSize}')
        else:
            # Read from image file to see if it contains the header code.
            bytes_to_read = len(self.settings.steg.PROGCODE)
            self.read_Data_From_Image(bytes_to_read)
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
                    self.read_Data_From_Image(bytes_to_read)
                    # Check if we read the expected number of bytes.
                    if (self.bytes_read != bytes_to_read):
                        self.log.error(f'Expected bytes: {bytes_to_read}; bytes read: {self.bytes_read}')
                    else:
                        self.pic_password = bool(int(self.code_bytes.decode('utf-8')))
                        self.log.info(f'Image file has password protection: {self.pic_password}')
                        # Get the length of the password.
                        bytes_to_read = self.settings.steg.PASSWDLENBYTES
                        self.read_Data_From_Image(bytes_to_read)
                        # Check if we read the expected number of bytes.
                        if (self.bytes_read != bytes_to_read):
                            self.log.error(f'Expected bytes: {bytes_to_read}; bytes read: {self.bytes_read}')
                        else:
                            self.pic_pw_len = int(self.code_bytes.decode('utf-8'))
                            self.log.debug(f'Password length: {self.pic_pw_len}')
                            # Get the password.
                            bytes_to_read = self.pic_pw_len
                            self.read_Data_From_Image(bytes_to_read)
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
    This method called if pic is encodded.
    """
    def get_Pic_Coded_Data(self):

        # Read the data type field.
        bytes_to_read = self.settings.steg.CODETYPEBYTES
        self.read_Data_From_Image(bytes_to_read)
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
                self.read_Data_From_Image(bytes_to_read)
                # Check if we read the expected number of bytes.
                if (self.bytes_read != bytes_to_read):
                    self.log.error(f'Expected bytes: {bytes_to_read}; bytes read: {self.bytes_read}')
                else:
                    self.pic_code_name_len = int(self.code_bytes.decode('utf-8'))
                    self.log.info(f'Image file has embedded file with filename length: {self.pic_code_name_len}')
                    # Read the filename.
                    bytes_to_read = self.pic_code_name_len
                    self.read_Data_From_Image(bytes_to_read)
                    # Check if we read the expected number of bytes.
                    if (self.bytes_read != bytes_to_read):
                        self.log.error(f'Expected bytes: {bytes_to_read}; bytes read: {self.bytes_read}')
                    else:
                        self.embedded_file_path = self.code_bytes.decode('utf-8')
                        self.log.info(f'Embedded file full path: {self.embedded_file_path}')
                        head, self.embedded_file_name = os.path.split(self.embedded_file_path)
                        self.log.info(f'Embedded file has filename: {self.embedded_file_name}')
                        # Now that we have the filename we can read the file size.
                        bytes_to_read = self.settings.steg.LENBYTES
                        self.read_Data_From_Image(bytes_to_read)
                        # Check if we read the expected number of bytes.
                        if (self.bytes_read != bytes_to_read):
                            self.log.error(f'Expected bytes: {bytes_to_read}; bytes read: {self.bytes_read}')
            else:
                # Unsupported embedded data type.
                self.log.error("Unsupported coded data type.")

    """
    Read buffer of data from image file.
    The data is read in chuncks, state updated
    as the reading progresses.
    """
    def read_Data_From_Image(self, bytes_to_read):
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

    """
    Write embedded data to a file.
    The name of the file is the same name
    the embedded file had.
    """
    def save_Embedded_File(self):

        self.log.info(f'Writing embedded file to disk : {self.to_embed_filepath}')

    """ 
    Read file and embed into the current image.
    Embed password if required.
    The name of the file is a class variable.

    Args:
        password:       True if password used (default False).
        pw:             Password if used (default blank)
    """

    def embed_File_To_Image(self, password=False, pw=""):

        self.log.info(f'Embedding into image from file : {self.to_embed_filepath}')

        # Initialise image file read parameters.
        self.row = 0
        self.col = 0
        self.plane = 0
        self.bit = 0
        self.bytes_written = 0
        self.code_bytes = []

        # Open file to be embedded.
        try:
            self.log.info(f'Opening file to embed : {self.to_embed_filepath}')
            with open(self.to_embed_filepath, mode='rb') as cf:

                # Need to add picCoder encoding to image first.
                frmt_string = ('%%s%%0%dd%%0%dd%%s%%0%dd%%0%dd%%s%%0%dd') % (self.settings.steg.PASSWDYNBYTES,
                                                                            self.settings.steg.PASSWDLENBYTES,
                                                                            self.settings.steg.CODETYPEBYTES,
                                                                            self.settings.steg.NAMELENBYTES,
                                                                            self.settings.steg.LENBYTES
                                                                            )
                picCode_hdr = frmt_string % (self.settings.steg.PROGCODE,
                                            int(password),
                                            len(pw),
                                            pw,
                                            self.settings.steg.CODETYPE_FILE,
                                            len(self.to_embed_filepath),
                                            self.to_embed_filepath,
                                            self.to_embed_file_size
                                            )

                self.log.info(f'Composed piCoder code to insert into image : {picCode_hdr}')
                self.log.info('Embedding picCoder encoding information into start of image.')
                self.write_Data_To_Image(bytearray(picCode_hdr, encoding='utf-8'))

                # Need to embed the actual file into the image.
                self.log.info('Embedding file into the image.')

                # Have the size of the file to embed, so can write the contents of the file.
                bytes_to_write = self.to_embed_file_size

                # Read and write a hung of data at a time.
                # Update the progress as we go.
                while bytes_to_write > 0:
                    if bytes_to_write > self.settings.steg.BYTESTACK:
                        bytes_this_write = self.settings.steg.BYTESTACK
                        bytes_to_write -= self.settings.steg.BYTESTACK
                    else:
                        bytes_this_write = bytes_to_write
                        bytes_to_write = 0

                    try:
                        # Read the hunk of data from the file.
                        byte_buffer = cf.read(bytes_this_write)
                        # And write the hunk into the image
                        self.write_Data_To_Image(byte_buffer)

                        # Check if we wrote the expected number of bytes.
                        if (self.bytes_written != bytes_this_write):
                            self.log.error(f'Expected byte hunk : {bytes_this_write}; bytes written : {self.bytes_written}')
                    except:
                        self.log.error(f'Failed to write code hunk to image.')
                        self.log.error(f'Exception returned : {str(e)}')       

        # Failed to open the file for reading.
        except Exception as e:
            self.log.error(f'Failed to open file to read from : {self.to_embed_filepath}')
            self.log.error(f'Exception returned : {str(e)}')

    """
    Write data (embed data) to image.
    Continue writing from where we left off.
    This function writes a chunk of data at a time,
    saving state of where it was up to as it goes.
    """
    def write_Data_To_Image(self, bytes_to_write):

        # Initialise loop counters counters.
        bytes_written = 0
        row_cnt = self.row
        col_cnt = self.col
        col_plane = self.plane
        bit_write = self.bit

        # Initialise embedding space to True.
        no_space = False

        # Intialise colour bit mask.
        col_mask = 1 << bit_write

        for byte_data in bytes_to_write:
            # Mask for reading byte bits.
            # Start from MSB so in bit order in the image (assume 8 bit byte).
            mask = 128

            # Cycle through 8 bits in each byte.
            for bitCnt in range(0, 8):
                # Check if we have any more space to store data.
                if no_space == True: break
    
                # Get next bit for byte in the array.
                if (byte_data & mask) == 0:
                    mapped_bit = 0
                else: mapped_bit = 1
                mapped_bit = mapped_bit << bit_write

                # Get current colour value, and modify with byte mapped bit.
                # col_pixel = QtGui.QColor(self.image.pixel(colCnt, rowCnt))
                # col_part = col_pixel.getRgb()[colPlane]
                col_pixel = self.image.getpixel((col_cnt, row_cnt))[col_plane]
                col_part = col_pixel[col_plane]
                col_part_modified = (col_part & ~col_mask) + mapped_bit

                # Modify the colour plane component that we are up to.
                if col_plane == 0:
                    col_pixel.setRed(col_part_modified)
                elif col_plane == 1:
                    col_pixel.setGreen(col_part_modified)
                elif col_plane == 2:
                    col_pixel.setBlue(col_part_modified)
                # Update the pixel colour now that the colour component has been modified.
                self.image.setPixel(col_cnt, row_cnt, col_pixel.rgb())
                
                # Shift mask right (towards LSB).
                mask = mask >> 1
    
                # Point to next column.
                col_cnt += 1
                if col_cnt == self.width:
                    col_cnt = 0
                    row_cnt += 1
                    # If we have reached the end of the image then go
                    # back to the top and go to the text bit.
                    if row_cnt == self.height:
                        row_cnt = 0
                        # Point to next colour plane.
                        # Take into account number of planes.
                        col_plane += 1
                        if col_plane == self.col_planes:
                            col_plane = 0
                            # Used all colour planes so move to next bit.
                            bit_write += 1
                            col_mask = col_mask << 1
                            if bit_write == 8:
                                # No more pixels
                                no_space = True
    
            # Increment characters read counter.
            bytes_written += 1

        # Update loop counters for next time.
        self.row = row_cnt
        self.col = col_cnt
        self.plane = col_plane
        self.bit = bit_write
        self.bytes_written = bytes_written
