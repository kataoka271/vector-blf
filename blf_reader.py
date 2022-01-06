from abc import ABC, abstractmethod
from io import SEEK_CUR, SEEK_END, BytesIO
from typing import BinaryIO, Callable, Generator, List, Optional, NamedTuple, Any
import datetime
import logging
import struct
import zlib

from blf_objtype import ObjectType


logging.basicConfig(level=logging.DEBUG, format='<%(levelname)s>%(message)s</%(levelname)s>')

# 0 = unknown, 2 = CANoe
APPLICATION_ID = 5

LOGG = b"LOGG"

# signature ("LOGG"), header_size,
# application_ID, application_major, application_minor, application_build,
# bin_log_major, bin_log_minor, bin_log_build, bin_log_patch,
# file_size, uncompressed_size, count_of_objects, count_of_objects_read,
# time_start (SYSTEMTIME), time_stop (SYSTEMTIME)
FILE_HEADER_STRUCT = struct.Struct("<4sLBBBBBBBBQQLL8H8H")

# Pad file header to this size
FILE_HEADER_SIZE = 144

LOBJ = b"LOBJ"

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


class SystemTime(NamedTuple):
    year: int
    month: int
    weekday: int
    day: int
    hour: int
    minute: int
    second: int
    millisecond: int


class Nanosecond(int):

    def __str__(self) -> str:
        return str(self / 1e9)


def nanosecond_to_systemtime(nanosecond: Nanosecond) -> SystemTime:
    t = datetime.datetime.fromtimestamp(nanosecond * 1e-9)
    return SystemTime(t.year,
                      t.month,
                      t.isoweekday() % 7,
                      t.day,
                      t.hour,
                      t.minute,
                      t.second,
                      t.microsecond // 1000)


def systemtime_to_nanosecond(systemtime: SystemTime) -> Nanosecond:
    try:
        t = datetime.datetime(systemtime.year,
                              systemtime.month,
                              systemtime.day,
                              systemtime.hour,
                              systemtime.minute,
                              systemtime.second,
                              systemtime.millisecond * 1000)
    except ValueError:
        return Nanosecond(0)
    else:
        return Nanosecond(int(round(t.timestamp() * 1e9)))


class BLFError(Exception):
    pass


class Message:

    def __init__(self, timestamp: Nanosecond = Nanosecond(0), id_: int = 0, channel: int = 0, dlc: int = 0, data: bytes = b"") -> None:
        self.timestamp = timestamp
        self.id = id_
        self.channel = channel
        self.dlc = dlc
        self.data = data
        self.data_length = len(data)
        self.is_extended_id = 0
        self.is_error_frame = False
        self.dir = 0
        self.rtr = 0
        self.fdf = 0
        self.brs = 0
        self.esi = 0

    def parse(self, fp: BinaryIO) -> None:
        raise NotImplementedError()

    def __str__(self) -> str:
        return '<message id="0x{id:x}" channel="{channel}" dlc="{dlc}" data="{data!s}" timestamp="{timestamp}" />'.format(
            id=self.id,
            channel=self.channel,
            dlc=self.dlc,
            data=self.data.hex(" "),
            timestamp=self.timestamp)


class CANMessage(Message):

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
        self.data_length = m[7]
        self.data = fp.read(self.data_length)
        self.channel = m[0]


class CANFDMessage64(Message):

    def parse(self, fp: BinaryIO) -> None:
        # channel, dlc, valid_payload_length_of_data, tx_count, arbitration_id,
        # frame_length, flags, bit_rate_used_in_arbitration_phase,
        # bit_rate_used_in_data_phase, time_offset_of_brs_field,
        # time_offset_of_crc_delimiter_field, bit_count, direction,
        # offset_if_extDataOffset_is_used, crc
        m = CAN_FD_MSG_64_STRUCT.unpack(fp.read(CAN_FD_MSG_64_STRUCT.size))
        self.id = m[4] & 0x1FFFFFFF
        self.is_extended_id = m[4] & CAN_MSG_EXT != 0
        self.dir = (m[6] & DIR_64) >> DIR_64_S
        self.rtr = 1 if m[6] & RTR_64 != 0 else 0
        self.fdf = 1 if m[6] & FDF_64 != 0 else 0
        self.brs = 1 if m[6] & BRS_64 != 0 else 0
        self.esi = 1 if m[6] & ESI_64 != 0 else 0
        self.dlc = m[1]
        self.data_length = m[2]
        self.data = fp.read(self.data_length)
        self.channel = m[0]


class CANErrorMessage(Message):

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

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.source_address = (0, 0, 0, 0, 0, 0)
        self.destination_address = (0, 0, 0, 0, 0, 0)
        self.ethernet_type = 0
        self.vlan_tpid = 0
        self.vlan_prio = 0
        self.vlan_cfi = 0
        self.vlan_id = 0

    def parse(self, fp: BinaryIO) -> None:
        # source_address, channel, destination_address, flags, ethernet_type, vlan_tpid,
        # vlan_tci, payload_length (max. 1500 bytes without Ethernet header)
        m = ETHERNET_FRM_STRUCT.unpack(fp.read(ETHERNET_FRM_STRUCT.size))
        self.source_address = struct.unpack("<BBBBBB", m[0])  # type: ignore
        self.destination_address = struct.unpack("<BBBBBB", m[2])  # type: ignore
        self.dir = m[3] & DIR
        self.ethernet_type = m[4]
        self.vlan_tpid = m[5]
        self.vlan_prio = (m[6] & 0xE000) >> 13
        self.vlan_cfi = (m[6] & 0x1000) >> 12
        self.vlan_id = m[6] & 0x0FFF
        self.data_length = m[7]
        self.data = fp.read(self.data_length)
        self.channel = m[1]

    def __str__(self) -> str:
        return ('<ethernet-frame sa="{sa}" da="{da}" ethernet_type="0x{ethernet_type:04x}" vlan_tpid="{vlan_tpid}" vlan_id="{vlan_id}" channel="{channel}" '
                'data="{data}" timestamp="{timestamp}" />').format(
            sa=":".join(map(str, self.source_address)),
            da=":".join(map(str, self.destination_address)),
            vlan_tpid=self.vlan_tpid,
            vlan_id=self.vlan_id,
            ethernet_type=self.ethernet_type,
            channel=self.channel,
            data=self.data.hex(" "),
            timestamp=self.timestamp)


class MessageFilter:

    def __init__(self, id_: Optional[int] = None, channel: Optional[int] = None, pred: Optional[Callable[[Message], bool]] = None) -> None:
        self.id = id_
        self.channel = channel
        self.pred = pred

    def match(self, msg: Message) -> bool:
        ret = True
        if self.id is not None:
            ret = ret and self.id == msg.id
        if self.channel is not None:
            ret = ret and self.channel == msg.channel
        if self.pred is not None:
            ret = ret and self.pred(msg)
        return ret


class BLFObject:

    def __init__(self) -> None:
        self._content: List[Message] = []

    @property
    def content(self) -> List[Message]:
        return self._content

    def parse(self, fp: BinaryIO) -> None:
        self.__read_header(fp)
        self.__read_content(fp)

    def parse_bytes(self, data: bytes) -> None:
        fp = BytesIO(data)
        self.__read_header(fp)
        self.__read_content(fp)

    def __read_header(self, fp: BinaryIO) -> None:
        data = fp.read(OBJ_HEADER_BASE_STRUCT.size)
        if not data:
            raise EOFError()
        header = OBJ_HEADER_BASE_STRUCT.unpack(data)
        if header[0] != LOBJ:
            raise BLFError("missing object magic number: LOBJ")
        # self.header_size = header[1]
        self.version = header[2]
        self.obj_size = header[3]
        self.obj_type = header[4]
        self.data_size = self.obj_size - OBJ_HEADER_BASE_STRUCT.size
        self.obj_curr = fp.tell() - OBJ_HEADER_BASE_STRUCT.size
        self.pad_size = self.data_size % 4
        self.obj_next = fp.tell() + self.data_size + self.pad_size  # read padding bytes

    def __read_content(self, fp: BinaryIO) -> None:
        self._content = []
        if self.obj_type == LOG_CONTAINER:
            m = LOG_CONTAINER_STRUCT.unpack(fp.read(LOG_CONTAINER_STRUCT.size))
            compression_method = m[0]
            uncompressed_size = m[1]
            size = self.data_size - LOG_CONTAINER_STRUCT.size
            data = fp.read(size)
            if compression_method == NO_COMPRESSION:
                fp_ = BytesIO(data)
            elif compression_method == ZLIB_DEFLATE:
                fp_ = BytesIO(zlib.decompress(data, 15, uncompressed_size))
            else:
                raise BLFError("unknown compression method")
            while True:
                try:
                    obj = BLFObject()
                    obj.parse(fp_)
                except EOFError:
                    break
                self._content.extend(obj.content)
        else:
            timestamp: int
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
                timestamp_ = Nanosecond(timestamp * 10000)
            else:
                timestamp_ = Nanosecond(timestamp)
            msg: Message
            if self.obj_type in (CAN_MESSAGE, CAN_MESSAGE2):
                msg = CANMessage(timestamp_)
                msg.parse(fp)
                self._content.append(msg)
            elif self.obj_type == CAN_FD_MESSAGE:
                msg = CANFDMessage(timestamp_)
                msg.parse(fp)
                self._content.append(msg)
            elif self.obj_type == CAN_FD_MESSAGE_64:
                msg = CANFDMessage64(timestamp_)
                msg.parse(fp)
                self._content.append(msg)
            elif self.obj_type == ETHERNET_FRAME:
                msg = EthernetFrame(timestamp_)
                msg.parse(fp)
                self._content.append(msg)
            elif self.obj_type == CAN_ERROR_EXT:
                msg = CANErrorMessage(timestamp_)
                msg.parse(fp)
                self._content.append(msg)
            else:
                try:
                    obj_type = ObjectType(self.obj_type).name
                except ValueError:
                    obj_type = str(self.obj_type)
                obj_data = fp.read(self.data_size)[:16].hex(' ')
                logging.debug(f'<unknown-object type="{obj_type}" data="{obj_data}" timestamp="{timestamp_}" />')
        fp.seek(self.obj_next)


class AbstractLogReader(ABC):

    @abstractmethod
    def __init__(self) -> None:
        raise NotImplementedError()

    @abstractmethod
    def read_message(self) -> Message:
        raise NotImplementedError()

    @abstractmethod
    def last_message(self) -> Message:
        raise NotImplementedError()

    @abstractmethod
    def seek(self, offset: int) -> None:
        raise NotImplementedError()

    @abstractmethod
    def tell(self) -> int:
        raise NotImplementedError()

    @property
    @abstractmethod
    def length(self) -> int:
        raise NotImplementedError()


class BLFReader(AbstractLogReader):
    header_size: int
    file_size: int
    start_timestamp: Nanosecond
    stop_timestamp: Nanosecond
    buffer: List[Message]
    content_offset: int
    current_offset: int
    msg_filter: MessageFilter

    def __init__(self, fp: BinaryIO, msg_filter: Optional[MessageFilter] = None) -> None:
        self.fp = fp
        self.buffer = []
        self.content_offset = 0
        self.current_offset = 0
        if msg_filter is None:
            self.msg_filter = MessageFilter()
        else:
            self.msg_filter = msg_filter
        self.__read_header()

    def __iter__(self) -> Generator[Message, None, None]:
        while True:
            try:
                obj = self.__read_object()
            except EOFError:
                break
            for msg in obj.content:
                yield msg

    def __read_header(self) -> None:
        data = self.fp.read(FILE_HEADER_STRUCT.size)
        header = FILE_HEADER_STRUCT.unpack(data)
        if header[0] != LOGG:
            raise BLFError("missing file magic number: LOGG")
        self.header_size = header[1]
        self.file_size = header[10]
        self.uncompressed_size = header[11]
        self.object_count = header[12]
        self.start_timestamp = systemtime_to_nanosecond(SystemTime._make(header[14:22]))
        self.stop_timestamp = systemtime_to_nanosecond(SystemTime._make(header[22:30]))
        self.fp.read(self.header_size - FILE_HEADER_STRUCT.size)
        self.content_offset = self.fp.tell()

    def __read_object(self) -> BLFObject:
        obj = BLFObject()
        obj.parse(self.fp)
        self.current_offset = self.fp.tell()
        return obj

    def __find_nearest_object(self) -> None:
        data = self.fp.read(4)
        self.fp.seek(-len(data), SEEK_CUR)
        if data == LOBJ:
            return
        while True:
            data = self.fp.read(10240)
            if len(data) < 4:
                raise EOFError()
            i = data.find(LOBJ)
            if i < 0:
                self.fp.seek(-3, SEEK_CUR)
            else:
                self.fp.seek(-len(data) + i, SEEK_CUR)
                break

    def read_message(self) -> Message:
        if self.current_offset != self.fp.tell():
            self.buffer = []
        while True:
            if not self.buffer:
                obj = self.__read_object()
                self.buffer.extend(obj.content)
            else:
                msg = self.buffer.pop()
                if self.msg_filter.match(msg):
                    return msg

    def last_message(self) -> Message:
        self.fp.seek(0, SEEK_END)
        while self.fp.tell() != 0:
            self.fp.seek(-102400, SEEK_CUR)
            buffer = self.fp.read(102400)
            i = len(buffer)
            while i >= 0:
                i = buffer.rfind(LOBJ, 0, i)
                obj = BLFObject()
                obj.parse_bytes(buffer[i:])
                for msg in reversed(obj.content):
                    if self.msg_filter.match(msg):
                        self.fp.seek(i - len(buffer), SEEK_CUR)
                        return msg
        raise BLFError("no message in this file")

    def seek(self, offset: int) -> None:
        if offset < 0:
            offset = 0
        if offset > self.file_size:
            offset = self.file_size
        self.fp.seek(offset + self.content_offset)
        self.__find_nearest_object()

    def tell(self) -> int:
        return self.fp.tell() - self.content_offset

    def set_msg_filter(self, msg_filter: MessageFilter) -> None:
        self.msg_filter = msg_filter

    def seek_timestamp(self, timestamp: int) -> None:
        timestamp_ = Nanosecond(timestamp)
        self.fp.seek(0, SEEK_END)
        offset = self.fp.tell() // 2
        self.fp.seek(offset)
        while True:
            obj = self.__read_object()
            if offset < OBJ_HEADER_BASE_STRUCT.size:
                return
            elif timestamp_ < obj.content[0].timestamp:
                offset = offset // 2
                self.fp.seek(-offset, SEEK_CUR)
            elif obj.content[-1].timestamp < timestamp_:
                next_obj = self.__read_object()
                if timestamp_ < next_obj.content[0].timestamp:
                    self.fp.seek(obj.obj_curr)
                    return
                offset = offset // 2
                self.fp.seek(offset, SEEK_CUR)
            else:
                self.fp.seek(obj.obj_curr)
                return

    @property
    def length(self) -> int:
        return self.file_size - self.content_offset


class Signal:
    pos: int
    msg: Message
    value: int

    def __init__(self, pos: int, msg: Message, value: int) -> None:
        self.pos = pos
        self.msg = msg
        self.value = value

    def __str__(self) -> str:
        return '<signal pos="{pos}" value="{value}" id="0x{id:x}" timestamp="{timestamp}" />'.format(
            pos=self.pos,
            value=self.value,
            id=self.msg.id,
            timestamp=self.msg.timestamp)


class SignalFactory:
    byte_offset: int
    bit_offset: int
    bit_length: int

    def __init__(self, byte_offset: int, bit_offset: int, bit_length: int) -> None:
        if bit_length > 64:
            raise ValueError("bit length is too large")
        self.byte_offset = byte_offset
        self.bit_offset = bit_offset
        self.bit_length = bit_length

    def get_signal_value(self, data: bytes) -> int:
        value = 0
        for byte in data[self.byte_offset:self.byte_offset + self.bit_length // 8 + 1]:
            value = (value << 8) | byte
        mask = (1 << self.bit_length) - 1
        shift = (8 - (7 - self.bit_offset + self.bit_length) % 8) % 8
        return (value >> shift) & mask

    def __call__(self, pos: int, msg: Message) -> Signal:
        return Signal(pos, msg, self.get_signal_value(msg.data))


def search_signals(blf: AbstractLogReader, signal: SignalFactory, resolution: int = 32) -> List[Signal]:
    msg = blf.read_message()
    sig_first = signal(blf.tell(), msg)
    msg = blf.last_message()
    sig_last = signal(blf.tell(), msg)
    stack = [sig_first, sig_last]
    results = []
    while len(stack) >= 2:
        last = stack.pop()
        first = stack.pop()
        dt = (last.pos - first.pos) // resolution
        if -300 < dt < 300:
            blf.seek(first.pos)
            while first.pos < last.pos:
                msg = blf.read_message()
                sig = signal(blf.tell(), msg)
                if first.value != sig.value:
                    results.append(sig)
                first = sig
        else:
            while first.pos < last.pos:
                blf.seek(last.pos - dt)
                msg = blf.read_message()
                sig = signal(blf.tell(), msg)
                if sig.value != last.value:
                    stack.append(sig)
                    stack.append(last)
                last = sig
    results.insert(0, sig_first)
    return results
