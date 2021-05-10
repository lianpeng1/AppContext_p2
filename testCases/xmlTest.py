import unittest

import sys
import os
curPath = os.path.abspath(os.path.dirname(__file__))
rootPath = os.path.split(curPath)[0]
sys.path.append(rootPath)

from src.xml_process import findxml

class xmlTest(unittest.TestCase):
    def test_xmltocsv(self):
        self.assertEqual(findxml('testCases/smali','testCases/xml/benign','testCases/xml/malware'),None)


if __name__ == '__main__':
    unittest.main()