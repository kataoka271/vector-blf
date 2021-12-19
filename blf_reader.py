from io import SEEK_CUR, SEEK_END, SEEK_SET, BytesIO
import datetime
import struct
import time
from typing import Generator, List, Optional, Tuple, BinaryIO
import zlib


# 0 = unknown, 2 = CANoe
APPLICATION_ID = 5

# signature ("LOGG"), header_size,
# application_ID, application_major, application_minor, application_build,
# bin_log_major, bin_log_minor, bin_log_build, bin_log_patch,
# file_size, uncompressed_size, count_of_objects, count_of_objects_read,
# time_start (SYSTEMTIME), time_stop (SYSTEMTIME)
FILE_HEADER_STRUCT = struct.Struct("<4sLBBBBBBBBQQLL8H8H")

# Pad file header to this size
FILE_HEADER_SIZE = 144

# signature ("LOBJ"), header_size, header_version, object_size, object_type
OBJ_HEADER_BASE_STRUCT = struct.Struct("<4sHHLL")

# flags, client_index, object_version, timestamp
OBJ_HEADER_V1_STRUCT = struct.Struct("<LHHQ")

# flags, timestamp_status, object_version, timestamp, original_timestamp
OBJ_HEADER_V2_STRUCT = struct.Struct("<LBxHQQ")

# compression_method, size_uncompressed
LOG_CONTAINER_STRUCT = struct.Struct("<H6xL4x")

# channel, flags, dlc, arbitration_id
CAN_MSG_STRUCT = struct.Struct("<HBBL")

# channel, flags, dlc, arbitration_id, frame_length, bit_count, FD_flags,
# valid data bytes
CAN_FD_MSG_STRUCT = struct.Struct("<HBBLLBBB5x")

# channel, dlc, valid_payload_length_of_data, tx_count, arbitration_id,
# frame_length, flags, bit_rate_used_in_arbitration_phase,
# bit_rate_used_in_data_phase, time_offset_of_brs_field,
# time_offset_of_crc_delimiter_field, bit_count, direction,
# offset_if_extDataOffset_is_used, crc
CAN_FD_MSG_64_STRUCT = struct.Struct("<BBBBLLLLLLLHBBL")

# source_address, channel, destination_address, flags, ethernet_type, vlan_tpid,
# vlan_tci, payload_length (max. 1500 bytes without Ethernet header)
ETHERNET_FRM_STRUCT = struct.Struct("<6sH6sHHHHH8x")

# channel, length, flags, ecc, position, dlc, frame_length, id, flags_ext, data
CAN_ERROR_EXT_STRUCT = struct.Struct("<HHLBBBxLLH2x")

# commented_event_type, foreground_color, background_color, relocatable,
# group_name_length, marker_name_length, description_length
GLOBAL_MARKER_STRUCT = struct.Struct("<LLL3xBLLL12x")


CAN_MESSAGE = 1
CAN_ERROR = 2
LOG_CONTAINER = 10
ETHERNET_FRAME = 71
CAN_ERROR_EXT = 73
CAN_MESSAGE2 = 86
GLOBAL_MARKER = 96
CAN_FD_MESSAGE = 100
CAN_FD_MESSAGE_64 = 101

NO_COMPRESSION = 0
ZLIB_DEFLATE = 2

CAN_MSG_EXT = 0x80000000
DIR = 0x3
RTR = 0x80
FDF = 0x1
BRS = 0x2
ESI = 0x4

# CAN FD 64 Flags
DIR_64 = 0x00C0
DIR_64_S = 6  # 6 bits shift
RTR_64 = 0x0010
FDF_64 = 0x1000
BRS_64 = 0x2000
ESI_64 = 0x4000

TIME_TEN_MICS = 0x00000001
TIME_ONE_NANS = 0x00000002

DLC_MAP = [0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64]


def timestamp_to_systemtime(timestamp: float) -> Tuple[int, int, int, int, int, int, int, int]:
    if timestamp is None or timestamp < 631152000:
        return (0, 0, 0, 0, 0, 0, 0, 0)
    t = datetime.datetime.fromtimestamp(timestamp)
    return (t.year, t.month, t.isoweekday() % 7, t.day,
            t.hour, t.minute, t.second, int(round(t.microsecond / 1000.0)))


def systemtime_to_timestamp(systemtime: Tuple[int, ...]) -> float:
    try:
        t = datetime.datetime(
            systemtime[0], systemtime[1], systemtime[3], systemtime[4],
            systemtime[5], systemtime[6], systemtime[7] * 1000)
        return time.mktime(t.timetuple()) + systemtime[7] / 1000.0
    except ValueError:
        return 0


class BLFError(Exception):
    pass


class Message:

    def __init__(self, timestamp: int = 0, id: int = 0, channel: int = 0, data: bytes = b"") -> None:
        self.timestamp = timestamp
        self.id = id
        self.channel = channel
        self.data = data
        self.data_length = len(data)

    def parse(self, fp: BinaryIO) -> None:
        raise NotImplementedError()


class CANMessage(Message):

    def __init__(self, timestamp: int) -> None:
        super().__init__()
        self.timestamp = timestamp

    def parse(self, fp: BinaryIO) -> None:
        # channel, flags, dlc, arbitration_id
        m = CAN_MSG_STRUCT.unpack(fp.read(CAN_MSG_STRUCT.size))
        self.id = m[3] & 0x1FFFFFFF
        self.is_extended_id = m[3] & CAN_MSG_EXT != 0
        self.dir = m[1] & DIR
        self.rtr = 1 if m[1] & RTR == 1 else 0
        self.fdf = 0
        self.brs = 0
        self.esi = 0
        self.dlc = m[2]
        self.data_length = self.dlc
        self.data = fp.read(self.data_length)
        self.channel = m[0]


class CANFDMessage(Message):

    def __init__(self, timestamp: int) -> None:
        super().__init__()
        self.timestamp = timestamp

    def parse(self, fp: BinaryIO) -> None:
        # channel, flags, dlc, arbitration_id, frame_length, bit_count,
        # FD_flags, valid_data_bytes
        m = CAN_FD_MSG_STRUCT.unpack(fp.read(CAN_FD_MSG_STRUCT.size))
        self.id = m[3] & 0x1FFFFFFF
        self.is_extended_id = m[3] & CAN_MSG_EXT != 0
        self.dir = m[1] & DIR
        self.rtr = 1 if m[1] & RTR != 0 else 0
        self.fdf = 1 if m[6] & FDF != 0 else 0
        self.brs = 1 if m[6] & BRS != 0 else 0
        self.esi = 1 if m[6] & ESI != 0 else 0
        self.dlc = m[2]
        self.data_length = DLC_MAP[self.dlc]
        self.data = fp.read(self.data_length)
        self.channel = m[0]


class CANFDMessage64(Message):

    def __init__(self, timestamp: int) -> None:
        super().__init__()
        self.timestamp = timestamp

    def parse(self, fp: BinaryIO) -> None:
        # channel, dlc, valid_payload_length_of_data, tx_count, arbitration_id,
        # frame_length, flags, bit_rate_used_in_arbitration_phase,
        # bit_rate_used_in_data_phase, time_offset_of_brs_field,
        # time_offset_of_crc_delimiter_field, bit_count, direction,
        # offset_if_extDataOffset_is_used, crc
        m = CAN_FD_MSG_64_STRUCT.unpack(fp.read(CAN_MSG_STRUCT.size))
        self.id = m[4] & 0x1FFFFFFF
        self.is_extended_id = m[4] & CAN_MSG_EXT != 0
        self.dir = (m[6] & DIR_64) >> DIR_64_S
        self.rtr = 1 if m[6] & RTR_64 != 0 else 0
        self.fdf = 1 if m[6] & FDF_64 != 0 else 0
        self.brs = 1 if m[6] & BRS_64 != 0 else 0
        self.esi = 1 if m[6] & ESI_64 != 0 else 0
        self.dlc = m[2]
        self.data_length = DLC_MAP[self.dlc]
        self.data = fp.read(self.data_length)
        self.channel = m[0]


class CANErrorMessage(Message):

    def __init__(self, timestamp: int) -> None:
        super().__init__()
        self.timestamp = timestamp

    def parse(self, fp: BinaryIO) -> None:
        # channel, length, flags, ecc, position, dlc, frame_length, id, flags_ext
        m = CAN_ERROR_EXT_STRUCT.unpack(fp.read(CAN_ERROR_EXT_STRUCT.size))
        self.is_error_frame = True
        self.id = m[7]
        self.is_extended_id = m[7] & CAN_MSG_EXT != 0
        self.rtr = 0
        self.fdf = 0
        self.brs = 0
        self.esi = 0
        self.dlc = m[5]
        self.data_length = self.dlc
        self.data = fp.read(self.data_length)
        self.channel = m[0]


class EthernetFrame(Message):

    def __init__(self, timestamp: int) -> None:
        super().__init__()
        self.timestamp = timestamp

    def parse(self, fp: BinaryIO) -> None:
        # source_address, channel, destination_address, flags, ethernet_type, vlan_tpid,
        # vlan_tci, payload_length (max. 1500 bytes without Ethernet header)
        m = ETHERNET_FRM_STRUCT.unpack(fp.read(ETHERNET_FRM_STRUCT.size))
        self.source_address = struct.unpack("<BBBBBB", m[0])
        self.destination_address = struct.unpack("<BBBBBB", m[2])
        self.dir = m[3] & DIR
        self.ethernet_type = m[4]
        self.vlan_tpid = m[5]
        self.vlan_prio = (m[6] & 0xE000) >> 13
        self.vlan_cfi = (m[6] & 0x1000) >> 12
        self.vlan_id = m[6] & 0x0FFF
        self.data_length = m[7]
        self.data = fp.read(self.data_length)
        self.channel = m[1]


class MessageFilter:

    def pass_(self, msg: Message) -> bool:
        return True


class BLFObject:

    def __init__(self, start_timestamp: float = 0) -> None:
        self.start_timestamp = start_timestamp
        self._content: List[Message] = []

    @property
    def content(self) -> List[Message]:
        return self._content

    def parse(self, fp: BinaryIO) -> None:
        self.__read_header(fp)
        self.__read_content(fp)

    def __read_header(self, fp: BinaryIO) -> None:
        data = fp.read(OBJ_HEADER_BASE_STRUCT.size)
        if not data:
            raise EOFError()
        header = OBJ_HEADER_BASE_STRUCT.unpack(data)
        if header[0] != b"LOBJ":
            raise BLFError("missing object magic number: LOBJ")
        # self.header_size = header[1]
        self.version = header[2]
        self.obj_size = header[3]
        self.obj_type = header[4]
        self.data_size = self.obj_size - OBJ_HEADER_BASE_STRUCT.size
        self.obj_curr = fp.tell() - OBJ_HEADER_BASE_STRUCT.size
        self.obj_next = fp.tell() + self.data_size % 4  # read padding bytes

    def __read_content(self, fp: BinaryIO) -> None:
        self._content = []
        if self.obj_type == LOG_CONTAINER:
            m = LOG_CONTAINER_STRUCT.unpack(fp.read(LOG_CONTAINER_STRUCT.size))
            compression_method = m[0]
            uncompressed_size = m[1]
            if compression_method == NO_COMPRESSION:
                fp_ = BytesIO(fp.read(self.data_size - LOG_CONTAINER_STRUCT.size))
            elif compression_method == ZLIB_DEFLATE:
                data = fp.read(self.data_size - LOG_CONTAINER_STRUCT.size)
                data = zlib.decompress(data, 15, uncompressed_size)
                fp_ = BytesIO(data)
            else:
                raise BLFError("unknown compression method")
            while True:
                try:
                    obj = BLFObject(self.start_timestamp)
                    obj.parse(fp_)
                except EOFError:
                    break
                self._content.extend(obj._content)
        else:
            if self.version == 1:
                m = OBJ_HEADER_V1_STRUCT.unpack(fp.read(OBJ_HEADER_V1_STRUCT.size))
                flags = m[0]
                timestamp = m[3]
            elif self.version == 2:
                m = OBJ_HEADER_V2_STRUCT.unpack(fp.read(OBJ_HEADER_V2_STRUCT.size))
                flags = m[0]
                timestamp = m[3]
            else:
                raise BLFError("unknown header version", self.version)
            if flags == TIME_TEN_MICS:
                factor = 10 * 1e-6
            else:
                factor = 1e-9
            self.timestamp = timestamp * factor + self.start_timestamp
            msg: Message
            if self.obj_type in (CAN_MESSAGE, CAN_MESSAGE2):
                msg = CANMessage(self.timestamp)
                msg.parse(fp)
                self._content.append(msg)
            elif self.obj_type == CAN_FD_MESSAGE:
                msg = CANFDMessage(self.timestamp)
                msg.parse(fp)
                self._content.append(msg)
            elif self.obj_type == CAN_FD_MESSAGE_64:
                msg = CANFDMessage64(self.timestamp)
                msg.parse(fp)
                self._content.append(msg)
            elif self.obj_type == ETHERNET_FRAME:
                msg = EthernetFrame(self.timestamp)
                msg.parse(fp)
                self._content.append(msg)
            elif self.obj_type == CAN_ERROR_EXT:
                pass
        fp.seek(self.obj_next)


class AbstractLogReader:

    def __init__(self) -> None:
        pass

    def read_message(self) -> Message:
        pass

    def seek(self, offset: int, whence: int = SEEK_SET) -> None:
        pass

    def tell(self) -> int:
        pass


class BLFReader(AbstractLogReader):

    def __init__(self, fp: BinaryIO, filter: Optional[MessageFilter] = None) -> None:
        self.fp = fp
        self.buffer: List[Message] = []
        self.content_offset = 0
        self.current_offset = 0
        if filter is None:
            self.filter = MessageFilter()
        self.__read_header()

    def __iter__(self) -> Generator[Message, None, None]:
        while True:
            try:
                obj = self.__read_object()
            except EOFError:
                break
            for msg in obj.content:
                yield msg

    def __find_nearest_object(self) -> None:
        data = self.fp.read(4)
        if data == b"LOBJ":
            self.fp.seek(-4, SEEK_CUR)
            return
        while True:
            data = self.fp.read(10240)
            if not data:
                raise EOFError()
            i = data.find(b"LOBJ")
            if i < 0:
                self.fp.seek(-3, SEEK_CUR)
            else:
                self.fp.seek(i - len(data), SEEK_CUR)
                break

    def __read_header(self) -> None:
        data = self.fp.read(FILE_HEADER_STRUCT.size)
        header = FILE_HEADER_STRUCT.unpack(data)
        if header[0] != b"LOGG":
            raise BLFError("missing file magic number: LOGG")
        self.header_size = header[1]
        self.file_size = header[10]
        self.uncompressed_size = header[11]
        self.object_count = header[12]
        self.start_timestamp = systemtime_to_timestamp(header[14:22])
        self.stop_timestamp = systemtime_to_timestamp(header[22:30])
        self.fp.read(self.header_size - FILE_HEADER_STRUCT.size)
        self.content_offset = self.fp.tell()

    def __read_object(self) -> BLFObject:
        obj = BLFObject(self.start_timestamp)
        obj.parse(self.fp)
        return obj

    def read_message(self) -> Message:
        if self.current_offset != self.fp.tell():
            self.buffer = []
        while True:
            if not self.buffer:
                obj = self.__read_object()
                self.buffer.extend(obj.content)
                self.current_offset = self.fp.tell()
            msg = self.buffer.pop()
            if self.filter.pass_(msg):
                return msg

    def seek(self, offset: int, whence: int = SEEK_SET) -> None:
        if offset < self.content_offset:
            offset = self.content_offset
        self.fp.seek(offset, whence)
        self.__find_nearest_object()

    def tell(self) -> int:
        return self.fp.tell()

    def set_filter(self, filter: MessageFilter) -> None:
        self.filter = filter

    def seek_seconds(self, seconds: int) -> None:
        target = self.start_timestamp + seconds
        self.fp.seek(0, SEEK_END)
        offset = self.fp.tell() // 2
        self.fp.seek(offset)
        while True:
            obj = self.__read_object()
            if offset < OBJ_HEADER_BASE_STRUCT.size:
                return
            elif target < obj.content[0].timestamp:
                offset = offset // 2
                self.fp.seek(-offset, SEEK_SET)
            elif obj.content[-1].timestamp < target:
                next_obj = self.__read_object()
                if target < next_obj.content[0].timestamp:
                    self.fp.seek(obj.obj_curr)
                    return
                offset = offset // 2
                self.fp.seek(offset, SEEK_SET)
            else:
                self.fp.seek(obj.obj_curr)
                return


class MyFilter(MessageFilter):

    def pass_(self, msg: Message) -> bool:
        return msg.id == 0x695 and msg.channel == 1


class MySignal:

    def __init__(self, msg: Message, offset: int) -> None:
        self.offset = offset
        self.msg = msg
        self.value = (msg.data[3] & 0x1FE) >> 1


def search_signals(blf: AbstractLogReader) -> List[MySignal]:
    n = 32
    msg = blf.read_message()
    sig_first = MySignal(msg, blf.tell())
    blf.seek(-1048576, SEEK_END)
    msg = blf.read_message()
    sig_last = MySignal(msg, blf.tell())
    stack = []
    stack.append(sig_first)
    stack.append(sig_last)
    results = []
    while len(stack) >= 2:
        last = stack.pop()
        first = stack.pop()
        if last.offset - first.offset < 1048576:  # 1M bytes
            offset = first.offset
            while offset < last.offset:
                msg = blf.read_message()
                offset = blf.tell()
                sig = MySignal(msg, offset)
                if first.value != sig.value:
                    results.append(sig)
                first = sig
        else:
            dt = (first.offset - last.offset) // n
            offset = last.offset
            while first.offset < offset:
                offset += dt
                blf.seek(offset)
                msg = blf.read_message()
                offset = blf.tell()
                sig = MySignal(msg, offset)
                if sig.value != last.value:
                    stack.append(sig)
                    stack.append(last)
                last = sig
    results.insert(0, sig_first)
    results.append(sig_last)
    return results
