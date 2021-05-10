import unittest

import sys
import os
curPath = os.path.abspath(os.path.dirname(__file__))
rootPath = os.path.split(curPath)[0]
sys.path.append(rootPath)

from src.disassemble import toSmali

class disassembleTest(unittest.TestCase):
    def test_disassemble(self):
        self.assertEqual(toSmali('testCases/apk','testCases/smali'),None)


if __name__ == '__main__':
    unittest.main()
