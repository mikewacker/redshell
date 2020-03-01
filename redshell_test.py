import unittest
import redshell

from shellnoob import ShellNoob

class RedShellTestCase(unittest.TestCase):

    def test_hex_dump(self):
        hexcode = "31db31c0b03c0f05"
        out = redshell.hex_dump(hexcode)
        expected_out = (
            "00000000: 31db 31c0 b03c 0f05                      1.1..<..\n")
        self.assertEqual(out, expected_out)

    def test_pba(self):
        snoob = ShellNoob(flag_64_bit=True, flag_intel=True)
        hexcode = "31db31c0b03c0f05"
        blacklist = "0f,31,90"
        inss = redshell.pba(snoob, hexcode, blacklist=blacklist)
        expected_inss = [
            redshell.InsX(ins="xor ebx,ebx", hex="31db", index=0, bytes=[
                redshell.ByteX(byte=b"\x31", hex="31", index=0)]),
            redshell.InsX(ins="xor eax,eax", hex="31c0", index=1, bytes=[
                redshell.ByteX(byte=b"\x31", hex="31", index=2)]),
            redshell.InsX(ins="mov al,0x3c", hex="b03c", index=2, bytes=[]),
            redshell.InsX(ins="syscall", hex="0f05", index=3, bytes=[
                redshell.ByteX(byte=b"\x0f", hex="0f", index=6)]),
        ]
        self.assertEqual(inss, expected_inss)

    def test_parse_prohibited_bytes_default(self):
        bytelist = redshell.parse_prohibited_bytes()
        expected_bytelist = b"\0\n"
        self.assertEqual(bytelist, expected_bytelist)

    def test_parse_prohibited_bytes_blacklist(self):
        blacklist = "0a,0d"
        bytelist = redshell.parse_prohibited_bytes(blacklist=blacklist)
        expected_bytelist = bytes.fromhex("0a0d")
        self.assertEqual(bytelist, expected_bytelist)

    def test_parse_prohibited_bytes_blacklist_range(self):
        blacklist = "00-08,0b-0c,0e-1f,7f"
        bytelist = redshell.parse_prohibited_bytes(blacklist=blacklist)
        expected_bytelist = bytes.fromhex(
            "0001020304050607080b0c0e0f101112131415161718191a1b1c1d1e1f7f")
        self.assertEqual(bytelist, expected_bytelist)

    def test_parse_prohibited_bytes_whitelist(self):
        whitelist = "09,0a,0d,20-7e,80-ff"
        bytelist = redshell.parse_prohibited_bytes(whitelist=whitelist)
        expected_bytelist = bytes.fromhex(
            "0001020304050607080b0c0e0f101112131415161718191a1b1c1d1e1f7f")
        self.assertEqual(bytelist, expected_bytelist)

    def test_error_parse_prohibited_bytes_whitelist_and_blacklist(self):
        with self.assertRaises(ValueError):
            redshell.parse_prohibited_bytes(blacklist="00", whitelist="00")

    def test_error_parse_prohibited_bytes_invalid_textlist(self):
        self._test_error_parse_prohibited_bytes_invalid_textlist("gg")
        self._test_error_parse_prohibited_bytes_invalid_textlist("0")
        self._test_error_parse_prohibited_bytes_invalid_textlist("00,00/")
        self._test_error_parse_prohibited_bytes_invalid_textlist("00-10-20")
        self._test_error_parse_prohibited_bytes_invalid_textlist("01-00")

    def _test_error_parse_prohibited_bytes_invalid_textlist(self, textlist):
        with self.assertRaises(redshell.ByteListParseError):
            redshell.parse_prohibited_bytes(blacklist=textlist)

    def test_disassemble_hex(self):
        hexcode = "31db31c0b03c0f05"
        snoob = ShellNoob(flag_64_bit=True, flag_intel=True)
        disassembler = redshell.HexDisassembler(snoob)
        inss = disassembler.disassemble(hexcode)
        expected_inss = [
            redshell.InsX(ins="xor ebx,ebx", hex="31db", index=0, bytes=[
                redshell.ByteX(byte=b"\x31", hex="31", index=0),
                redshell.ByteX(byte=b"\xdb", hex="db", index=1)]),
            redshell.InsX(ins="xor eax,eax", hex="31c0", index=1, bytes=[
                redshell.ByteX(byte=b"\x31", hex="31", index=2),
                redshell.ByteX(byte=b"\xc0", hex="c0", index=3)]),
            redshell.InsX(ins="mov al,0x3c", hex="b03c", index=2, bytes=[
                redshell.ByteX(byte=b"\xb0", hex="b0", index=4),
                redshell.ByteX(byte=b"\x3c", hex="3c", index=5)]),
            redshell.InsX(ins="syscall", hex="0f05", index=3, bytes=[
                redshell.ByteX(byte=b"\x0f", hex="0f", index=6),
                redshell.ByteX(byte=b"\x05", hex="05", index=7)]),
        ]
        self.assertEqual(inss, expected_inss)

    def test_prohibited_bytes_analyzer(self):
        prohibited_bytes = bytes.fromhex("0f3190")
        inss = [
            redshell.InsX(ins="xor ebx,ebx", hex="31db", index=0, bytes=[
                redshell.ByteX(byte=b"\x31", hex="31", index=0),
                redshell.ByteX(byte=b"\xdb", hex="db", index=1)]),
            redshell.InsX(ins="xor eax,eax", hex="31c0", index=1, bytes=[
                redshell.ByteX(byte=b"\x31", hex="31", index=2),
                redshell.ByteX(byte=b"\xc0", hex="c0", index=3)]),
            redshell.InsX(ins="mov al,0x3c", hex="b03c", index=2, bytes=[
                redshell.ByteX(byte=b"\xb0", hex="b0", index=4),
                redshell.ByteX(byte=b"\x3c", hex="3c", index=5)]),
            redshell.InsX(ins="syscall", hex="0f05", index=3, bytes=[
                redshell.ByteX(byte=b"\x0f", hex="0f", index=6),
                redshell.ByteX(byte=b"\x05", hex="05", index=7)]),
        ]
        analyzer = redshell.ProhibitedBytesAnalyzer(prohibited_bytes)
        inss = analyzer.analyze(inss)
        expected_inss = [
            redshell.InsX(ins="xor ebx,ebx", hex="31db", index=0, bytes=[
                redshell.ByteX(byte=b"\x31", hex="31", index=0)]),
            redshell.InsX(ins="xor eax,eax", hex="31c0", index=1, bytes=[
                redshell.ByteX(byte=b"\x31", hex="31", index=2)]),
            redshell.InsX(ins="mov al,0x3c", hex="b03c", index=2, bytes=[]),
            redshell.InsX(ins="syscall", hex="0f05", index=3, bytes=[
                redshell.ByteX(byte=b"\x0f", hex="0f", index=6)]),
        ]
        self.assertEqual(inss, expected_inss)

if __name__ == "__main__":
    unittest.main()
