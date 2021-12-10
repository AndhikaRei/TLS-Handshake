from __future__ import annotations

import os
from io import BufferedReader
from sys import byteorder
from typing import ClassVar, List

MAX_SEGMENT = 32780
MAX_SIZE = 32768


class SEGMENT_TYPE:
    META: ClassVar[str] = 'META'
    SYN: ClassVar[str] = 'SYN'
    DATA: ClassVar[str] = 'DATA'
    ACK: ClassVar[str] = 'ACK'
    SYNACK: ClassVar[str] = 'SYN,ACK'
    FIN: ClassVar[str] = 'FIN'
    FINACK: ClassVar[str] = 'FIN,ACK'

FLAGS = {
    SEGMENT_TYPE.META: 0b00000001,
    SEGMENT_TYPE.SYN: 0b01000000,
    SEGMENT_TYPE.DATA: 0b00000000,
    SEGMENT_TYPE.ACK: 0b00001000,
    SEGMENT_TYPE.SYNACK: 0b01001000,
    SEGMENT_TYPE.FIN: 0b10000000,
    SEGMENT_TYPE.FINACK: 0b10001000,
}

def ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b

def string_to_asciis(string: str) -> List[int]:
    result: List[int] = []
    for c in string:
        result.append(ord(c))
    return result

def asciis_to_string(asciis: List[int]) -> str:
    result = ''
    for c in asciis:
        if c != 0:
            result = result + chr(c)
    return result

def bytes_to_int_list(b: bytes) -> List[int]:
    return list(map(int, b))

class Segment:
    """
    Represents a segment of a file
    """
    def __init__(self, type: str='DATA', seq_number: int=2, ack_number: int=0, data: List[int]=[0 for _ in range(MAX_SIZE)]) -> None:
        """
        @param `type` must be `SYN`, `DATA`(default), `ACK`, `SYNACK`, `META`, `FIN`, `FINACK`.
        @param `seq_number` the number of current segment
        @param `ack_number` the `seq_number` of last received ACK
        @param `data` contains every byte of the file content
        """
        self.__sequence = seq_number
        self.__ack = ack_number
        if len(data) % 2:
            data.append(0)

        try:
            self.__flags = FLAGS[type]
        except:
            self.__flags = FLAGS[SEGMENT_TYPE.DATA]

        self.__data = data
        self.__checksum = self.__count_checksum()

    def __to_bytes_no_checksum(self):
        """
        Return the byte representation of segment without checksum.
        """
        seq_num = bytearray(self.sequence.to_bytes(4, byteorder))
        ack_num = bytearray(self.ack.to_bytes(4, byteorder))
        flag = bytearray(self.flags.to_bytes(1, byteorder))
        data = bytearray(self.data)
        combined = seq_num + ack_num + flag + bytearray(1) + data
        return combined

    def __count_checksum(self) -> int:
        all_contents = self.__to_bytes_no_checksum()
        segment_length = len(all_contents)
        checksum = 0
        for i in range(0, segment_length, 2):
            checksum = Segment.__sum_of_two(checksum, int.from_bytes(bytearray([all_contents[i], all_contents[i + 1]]), byteorder))
        checksum = ~checksum
        return checksum & 0xFFFF

    def __count_checksum_2(self) -> int:
        """
        Version two, using integer operations
        """
        checksum = Segment.__sum_of_two(self.sequence & 0xFFFF, (self.sequence >> 16) & 0xFFFF)
        checksum = Segment.__sum_of_two(self.ack & 0xFFFF, checksum)
        checksum = Segment.__sum_of_two((self.ack >> 16) & 0xFFFF, checksum)
        checksum = Segment.__sum_of_two(self.flags << 16, checksum)
        for i in range(0, len(self.data), 2):
            two_bytes = (self.data[i] << 16) | (self.data[i + 1] & 0xFFFF)
            checksum = Segment.__sum_of_two(two_bytes, checksum)
        checksum = ~checksum
        return checksum & 0xFFFF

    def to_bytes(self):
        """
        Return the byte representation of segment.
        """
        seq_num = bytearray(self.sequence.to_bytes(4, byteorder))
        ack_num = bytearray(self.ack.to_bytes(4, byteorder))
        flag = bytearray(self.flags.to_bytes(1, byteorder))
        checksum = bytearray(self.__checksum.to_bytes(2, byteorder))
        data = bytearray(self.data)
        combined = seq_num + ack_num + flag + bytearray(1) + checksum + data

        return combined

    def from_bytes(self, bytesSegment: bytearray) -> Segment:
        self.__sequence = int.from_bytes(bytesSegment[0: 4], byteorder)
        self.__ack  = int.from_bytes(bytesSegment[4: 8], byteorder)
        self.__flags = bytesSegment[8]
        self.__checksum = int.from_bytes(bytesSegment[10: 12], byteorder)
        self.__data = bytesSegment[12:]

        return self

    def __len__(self) -> int:
        return len(self.data)

    def __str__(self) -> str:
        return f'{self.sequence}\n{self.ack}\n{self.flags} {self.__checksum}\n{self.data}'

    @property
    def sequence(self) -> int:
        return self.__sequence

    @sequence.setter
    def sequence(self, value) -> None:
        self.__sequence = value
        self.__checksum = self.__count_checksum()

    @property
    def ack(self) -> int:
        return self.__ack

    @ack.setter
    def ack(self, value: int) -> None:
        self.__ack = value
        self.__checksum = self.__count_checksum()

    @property
    def flags(self) -> int:
        return self.__flags

    @flags.setter
    def flags(self, value: int) -> None:
        self.__flags = value
        self.__checksum = self.__count_checksum()

    @property
    def data(self) -> List[int]:
        return self.__data

    @property
    def valid(self) -> bool:
        all_contents = self.to_bytes()
        segment_length = len(all_contents)
        checksum = 0
        for i in range(0, segment_length, 2):
            checksum = Segment.__sum_of_two(checksum, int.from_bytes(bytearray([all_contents[i], all_contents[i + 1]]), byteorder))
        checksum = ~checksum
        return (checksum & 0xFFFF) == 0

    @property
    def is_meta(self) -> bool:
        return self.flags == FLAGS[SEGMENT_TYPE.META]

    @property
    def is_syn(self) -> bool:
        return self.flags == FLAGS[SEGMENT_TYPE.SYN]

    @property
    def is_ack(self) -> bool:
        return self.flags == FLAGS[SEGMENT_TYPE.ACK]

    @property
    def is_synack(self) -> bool:
        return self.flags == FLAGS[SEGMENT_TYPE.SYNACK]

    @property
    def is_fin(self) -> bool:
        return self.flags == FLAGS[SEGMENT_TYPE.FIN]
    
    @property
    def is_finack(self) -> bool:
        return self.flags == FLAGS[SEGMENT_TYPE.FINACK]

    @property
    def is_data(self) -> bool:
        return self.flags == FLAGS[SEGMENT_TYPE.DATA]

    @property
    def type(self) -> str:
        if self.is_meta: return SEGMENT_TYPE.META
        if self.is_ack: return SEGMENT_TYPE.ACK
        if self.is_data: return SEGMENT_TYPE.DATA
        if self.is_fin: return SEGMENT_TYPE.FIN
        if self.is_finack: return SEGMENT_TYPE.FINACK
        if self.is_syn: return SEGMENT_TYPE.SYN
        if self.is_synack: return SEGMENT_TYPE.SYNACK

    @staticmethod
    def __sum_of_two(first: int, second: int) -> int:
        assert first & 0xFFFF == first
        assert second & 0xFFFF == second

        total = first + second
        # Both `first` and `second` are two bytes
        # So, `carry` is either 1 or 0
        carry = (total >> 16) & 0xFFFF

        if carry == 0:
            return total
        return Segment.__sum_of_two(total & 0xFFFF, carry)

    @staticmethod
    def verbose(segment:Segment, action: str="Sent", additional_explaination: str=""):
        print(f'[Segment SEQ={segment.sequence} {("ACK="+str(segment.ack)) if segment.ack else ""} CTL={segment.type}] {action}  {(" <- " + additional_explaination) if additional_explaination else ""}')

    @staticmethod
    def from_file(file: BufferedReader, filename: str="", starting_sequence: int=1) -> List[Segment]:
        result: List[Segment] = []
        file_metadata = string_to_asciis(filename)
        file_meta_size = len(file_metadata)

        # Send file name
        num_of_meta_segments = ceil_div(file_meta_size, MAX_SIZE)
        print(f'Sending metadata in {num_of_meta_segments} segments.')
        for i in range(0, num_of_meta_segments, 1):
            result.append(Segment(type=SEGMENT_TYPE.META, seq_number=starting_sequence, data=file_metadata[i * MAX_SIZE: (i + 1) * MAX_SIZE]))
            starting_sequence += 1

        file.seek(0)
        file_bytes = file.read()
        file_size = len(file_bytes)

        # Literal ceiling method
        num_of_segments = ceil_div(file_size, MAX_SIZE)
        print(f'Size of {filename} is {file_size} bytes.')
        print(f'Maximum payload size is {MAX_SIZE} bytes. The file content will be sent in {num_of_segments} segment(s).')
        for i in range(0, num_of_segments, 1):
            result.append(Segment(type="DATA", seq_number=starting_sequence, data=bytes_to_int_list(file_bytes[i * MAX_SIZE: (i + 1) * MAX_SIZE])))
            starting_sequence += 1
        return result

if __name__ == '__main__':
    syn_segment = Segment(type="SYN", seq_number=0)
    file = open('./in/carbon.png', 'rb')
    segments = Segment.from_file(file, 'carbon.png')
    segments[0].ack = 5
