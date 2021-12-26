from blf_reader import Message, AbstractLogReader, search_signals
import pprint


class DummyReader(AbstractLogReader):

    def __init__(self) -> None:
        super().__init__()
        self.messages = [Message(i, 0x695, 1, b"000\x00") for i in range(0, 30)] + \
                        [Message(i, 0x695, 1, b"000\x02") for i in range(30, 45)] + \
                        [Message(i, 0x695, 1, b"000\x04") for i in range(45, 66)] + \
                        [Message(i, 0x695, 1, b"000\x08") for i in range(66, 87)] + \
                        [Message(i, 0x695, 1, b"000\x0c") for i in range(87, 88)] + \
                        [Message(i, 0x695, 1, b"000\x10") for i in range(88, 167)] + \
                        [Message(i, 0x695, 1, b"000\x14") for i in range(167, 10167)] + \
                        [Message(i, 0x695, 1, b"000\x12") for i in range(10167, 10194)] + \
                        [Message(i, 0x695, 1, b"000\x07") for i in range(10194, 10199)] + \
                        [Message(i, 0x695, 1, b"000\x00") for i in range(10199, 10222)]
        self.i = 0

    def read_message(self) -> Message:
        if self.i >= len(self.messages):
            raise EOFError()
        msg = self.messages[self.i]
        self.i += 1
        return msg

    def last_message(self) -> Message:
        self.i = len(self.messages) - 1
        return self.messages[-1]

    def seek(self, offset: float) -> None:
        self.i = int((len(self.messages) - 1) * max(0, min(1, offset)))

    def tell(self) -> float:
        return self.i / (len(self.messages) - 1)

    @property
    def length(self) -> int:
        return len(self.messages)


if __name__ == "__main__":
    pprint.pprint(search_signals(DummyReader()))
