#!/usr/bin/env python3

import argparse
import collections
from shellnoob import ShellNoob
import sys

# Create argument parser.

parser = argparse.ArgumentParser(
    description="Helps home shellcode-based attacks using shellnoob.",
    epilog="Example: redshell --hex shellcode.hex --blacklist 00,09-0d,20")
input_group = parser.add_mutually_exclusive_group(required=True)
input_group.add_argument(
    "--hex", type=argparse.FileType("r"),
    metavar="PATH", help=".hex file containing shellcode")
input_group.add_argument("--asm", help="assembly instructions")
pb_group = parser.add_mutually_exclusive_group()
pb_group.add_argument(
    "--blacklist",
    metavar="LIST", help="list of blacklisted bytes or byte ranges")
pb_group.add_argument(
   "--whitelist",
   metavar="LIST", help="list of whitelisted bytes or byte ranges")
parser.add_argument(
    "--arch", choices=["32", "64"], default="64",
    help="32-bit or 64-bit architecture (default: 64)")
parser.add_argument(
    "--asm-syntax", choices=["intel", "att"], default="intel",
    help="assembly syntax (default: intel)")


# Command-line interface.

def main(argv):
    """Main method."""
    args = parser.parse_args(argv[1:])

    # Build the ShellNoob instance.
    is_64 = args.arch == 64
    is_intel = args.asm_syntax == "intel"
    snoob = ShellNoob(is_64, is_intel)

    # Extract the hexcode.
    if args.asm:
        hexcode = snoob.asm_to_hex(args.asm)
        print("Hexcode\n-------\n{:s}\n".format(hexcode))
    else:
        with args.hex as f:
            hexcode = f.read()

    # Run and print the analysis.
    inss = pba(snoob, hexcode, args.blacklist, args.whitelist)
    print_pba(inss)

def print_pba(inss):
    """Prints the prohibited bytes."""
    print("Assembly\n--------")
    num_prohibited_bytes = 0
    for ins in inss:
        print("{:32s} # {:s}".format(ins.ins, ins.hex))
        for byte in ins.bytes:
            print("    {:s} [index 0x{:x}, column {:d}]".format(
                byte.hex, byte.index, 2 * byte.index + 1))
            num_prohibited_bytes += 1
    print()
    if num_prohibited_bytes:
        print("prohibited bytes found")
    else:
        print("no prohibited bytes found")


# Analyze shellcode for prohibited bytes.

InsX = collections.namedtuple("InsX", ["ins", "hex", "bytes", "index"])
ByteX = collections.namedtuple("ByteX", ["byte", "hex", "index"])

def pba(snoob, hexcode, blacklist=None, whitelist=None):
    """Runs the prohibited bytes analysis againsts the shellcode.

    Args:
        snoob: ShellNoob instance
        hexcode: shellcode in hex form
        blacklist: text blacklist of bytes, can't be used with whitelist
        whitelist: text whitelist of bytes, can't be used with blacklist

    Returns:
        all instructions, and prohibited bytes for each instruction
    """
    prohibited_bytes = parse_prohibited_bytes(blacklist, whitelist)
    disassembler = HexDisassembler(snoob)
    inss = disassembler.disassemble(hexcode)
    analyzer = ProhibitedBytesAnalyzer(prohibited_bytes)
    return analyzer.analyze(inss)

def parse_prohibited_bytes(blacklist=None, whitelist=None):
    """Parses the text input into a blacklist of bytes."""
    if blacklist and whitelist:
        raise ValueError("can't use both a blacklist and a whitelist")
    if not (blacklist or whitelist):
        return b"\0\n"
    if blacklist:
        return _parse_textlist(blacklist)
    else:
        bytelist = _parse_textlist(whitelist)
        return _invert_bytelist(bytelist)

class ByteListParseError(Exception):
    """Error parsing a byte list."""

    def __init__(self, message, token, parsed):
        """Creates an error that includes token and the parsed input."""
        message = '{:s} [token="{:s}", parsed="{:s}"]'.format(
            message, token, parsed)
        Exception.__init__(self, message)

def _parse_textlist(textlist):
    """Parses the byte list from text input."""
    bytelist = b""
    index = 0
    while index < len(textlist):
        # Parse a byte.
        byte = _parse_byte(textlist, index)
        index += 2

        # Parse a ',', '-', or END.
        token = textlist[index:index + 1]
        if token in ["", ","]:
            bytelist += byte
            index += 1
            continue
        if token != "-":
            raise ByteListParseError(
                "expected ',' or '-'", token, textlist[:index])
        index += 1

        # Parse the other byte in the byte range.
        byte2 = _parse_byte(textlist, index)
        byterange = _build_byterange(byte, byte2, textlist, index)
        bytelist += byterange
        index += 2

        # Parse a ',' or END.
        token = textlist[index:index + 1]
        if token not in ["", ","]:
            raise ByteListParseError("expected ','", token, textlist[:index])
        index += 1
    return bytelist

def _parse_byte(textlist, index):
    """Parses a byte from a hex code."""
    token = textlist[index:index + 2]
    try:
        return bytes.fromhex(token)
    except ValueError:
        raise ByteListParseError("expected a hex byte", token, textlist[:index])

def _build_byterange(begin_byte, end_byte, textlist, index):
    """Builds an inclusive range of bytes."""
    begin_code = ord(begin_byte)
    end_code = ord(end_byte)
    if end_code < begin_code:
        raise ByteListParseError(
            "backwards byte range", begin_byte.hex(), textlist[:index])
    return bytes(range(begin_code, end_code + 1))

def _invert_bytelist(bytelist):
    """Inversts a bytelist."""
    return bytes([code for code in range(256) if code not in bytelist])

class HexDisassembler(object):
    """Disassembles hexcode via ShellNoob."""

    def __init__(self, snoob):
        """Creates a dissasembler from a ShellNoob instance."""
        self._snoob = snoob

    def disassemble(self, hexcode):
        """Dissasembles the hexcode, producing instructions and their bytes."""
        inss = self._snoob.hex_to_inss(hexcode)
        insxs = []
        byte_offset = 0
        for index, ins in enumerate(inss):
            insx = self._create_insx(ins, index, byte_offset)
            insxs.append(insx)
            byte_offset += int(len(insx.hex) / 2)
        return insxs

    def _create_insx(self, ins, index, byte_offset):
        """Creates the extended instruction information."""
        hex = self._snoob.ins_to_hex(ins)
        bites = bytes.fromhex(hex)
        bytexs = []
        for byte_index, code in enumerate(bites):
            byte = bytes([code])
            byte_hex = byte.hex()
            byte_index = byte_offset + byte_index
            bytex = ByteX(byte=byte, hex=byte_hex, index=byte_index)
            bytexs.append(bytex)
        return InsX(ins=ins, hex=hex, bytes=bytexs, index=index)

class ProhibitedBytesAnalyzer(object):
    """Analyzes bytecode for prohibited bytes."""

    def __init__(self, prohibited_bytes):
        """Creates an analyzer from the prohibited bytes."""
        self._prohibited_bytes = prohibited_bytes

    def analyze(self, inss):
        """Filters out bytes from the instructions, leaving prohibited bytes."""
        new_inss = []
        for ins in inss:
            new_bytes = [
                byte
                for byte in ins.bytes
                if byte.byte in self._prohibited_bytes]
            new_ins = InsX(
                ins=ins.ins, hex=ins.hex, bytes=new_bytes, index=ins.index)
            new_inss.append(new_ins)
        return new_inss


if __name__ == "__main__":
    main(sys.argv)
