import unittest
import redshell

from shellnoob import ShellNoob
import warnings

class RedShellTestCase(unittest.TestCase):

    def setUp(self):
        warnings.filterwarnings("ignore", category=ResourceWarning)

    def testExtractHexCode_Asm(self):
        self._testExtractHexCode_File("asm")

    def testExtractHexCode_Obj(self):
        self._testExtractHexCode_File("obj")

    def testExtractHexCode_Bin(self):
        self._testExtractHexCode_File("bin")

    def testExtractHexCode_Hex(self):
        self._testExtractHexCode_File("hex")

    def testExtractHexCode_C(self):
        self._testExtractHexCode_File("c")

    def testExtractHexCode_ShellStorm(self):
        snoob = ShellNoob(flag_64_bit=False, flag_intel=True)
        hexcode = redshell.extract_hex_code(snoob, "shellstorm", "827")
        expected_hexcode = (
            "31c050682f2f7368682f62696e89e3505389e1b00bcd80")
        self.assertEqual(hexcode, expected_hexcode)

    def testExtractHexCode_AsmText(self):
        snoob = ShellNoob(flag_64_bit=False, flag_intel=True)
        hexcode = redshell.extract_hex_code(snoob, "asm_text", "int 0x80")
        expected_hexcode = "cd80"
        self.assertEqual(hexcode, expected_hexcode)

    def _testExtractHexCode_File(self, fmt):
        snoob = ShellNoob(flag_64_bit=False, flag_intel=True)
        path = "testdata/shellcode.{:s}".format(fmt)
        hexcode = redshell.extract_hex_code(snoob, fmt, path)
        expected_hexcode = (
            "31c050682f2f7368682f62696e89e3505389e1b00bcd80")
        self.assertEqual(hexcode, expected_hexcode)

    def testHexDump(self):
        hexcode = "31db31c0b03c0f05"
        out = redshell.hex_dump(hexcode)
        expected_out = (
            "00000000: 31db 31c0 b03c 0f05                      1.1..<..\n")
        self.assertEqual(out, expected_out)

    def testProhibitedBytesAnalysis(self):
        snoob = ShellNoob(flag_64_bit=True, flag_intel=True)
        hexcode = "31db31c0b03c0f05"
        blacklist = "0f,31,90"
        inss = redshell.prohibited_bytes_analysis(
            snoob, hexcode, blacklist=blacklist)
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

    def testParseProhibitedBytes_Default(self):
        bytelist = redshell.parse_prohibited_bytes()
        expected_bytelist = b"\0\n"
        self.assertEqual(bytelist, expected_bytelist)

    def testParseProhibitedBytes_Blacklist(self):
        blacklist = "0a,0d"
        bytelist = redshell.parse_prohibited_bytes(blacklist=blacklist)
        expected_bytelist = bytes.fromhex("0a0d")
        self.assertEqual(bytelist, expected_bytelist)

    def testParseProhibitedBytes_BlacklistRange(self):
        blacklist = "00-08,0b-0c,0e-1f,7f"
        bytelist = redshell.parse_prohibited_bytes(blacklist=blacklist)
        expected_bytelist = bytes.fromhex(
            "0001020304050607080b0c0e0f101112131415161718191a1b1c1d1e1f7f")
        self.assertEqual(bytelist, expected_bytelist)

    def testParseProhibitedBytes_Whitelist(self):
        whitelist = "09,0a,0d,20-7e,80-ff"
        bytelist = redshell.parse_prohibited_bytes(whitelist=whitelist)
        expected_bytelist = bytes.fromhex(
            "0001020304050607080b0c0e0f101112131415161718191a1b1c1d1e1f7f")
        self.assertEqual(bytelist, expected_bytelist)

    def testParseProhibitedBytes_Error_BlacklistAndWhitelist(self):
        with self.assertRaises(ValueError):
            redshell.parse_prohibited_bytes(blacklist="00", whitelist="00")

    def testParseProhibitedBytes_Error_InvalidTextlist(self):
        self._testParseProhibitedBytes_Error_InvalidTextlist("gg")
        self._testParseProhibitedBytes_Error_InvalidTextlist("0")
        self._testParseProhibitedBytes_Error_InvalidTextlist("00,00/")
        self._testParseProhibitedBytes_Error_InvalidTextlist("00-10-20")
        self._testParseProhibitedBytes_Error_InvalidTextlist("01-00")

    def _testParseProhibitedBytes_Error_InvalidTextlist(self, textlist):
        with self.assertRaises(redshell.ByteListParseError):
            redshell.parse_prohibited_bytes(blacklist=textlist)

    def testDisassembleHex(self):
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

    def testProhibitedBytesAnalyzer(self):
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
