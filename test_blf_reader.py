from blf_reader import BLFReader, MessageFilter
import sys


def test() -> None:
    if len(sys.argv) >= 2:
        fp = open(sys.argv[1], "rb")
    else:
        fp = open(".\\sample\\logfile.blf", "rb")
    blf = BLFReader(fp, MessageFilter())
    blf.seek(0)
    try:
        print(blf.read_message())
        print(blf.read_message())
        print(blf.read_message())
        print(blf.read_message())
    except EOFError:
        pass


if __name__ == '__main__':
    test()
