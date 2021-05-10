import unittest

import sys
import os
curPath = os.path.abspath(os.path.dirname(__file__))
rootPath = os.path.split(curPath)[0]
sys.path.append(rootPath)

from src.identifyActivationEvent import *

class identifyTest(unittest.TestCase):
    def test_processStr(self):
        result = processStr('int onStartCommand()>')
        self.assertEqual(result,'int onStartCommand   ')

    def test_isLifecycle(self):
        result = isLifecyle('<com.convertoman.proin.ProinActivity: void onCreate(android.os.Bundle)>')
        self.assertEqual(result,True)

    def test_isNotLifecycle(self):
        result = isLifecyle('<com.apps.android.Main$2: void onClick(android.content.DialogInterface,int)>')
        self.assertEqual(result,False)

    def test_isEventHandler(self):
        result = isEventHandler('<com.apps.android.Main$2: void onClick(android.content.DialogInterface,int)>')
        self.assertEqual(result,'onClick')

    def test_isNotEventHandler(self):
        result = isEventHandler('<com.convertoman.proin.ProinActivity: void onCreate(android.os.Bundle)>')
        self.assertEqual(result,None)

    def test_hasIntentFilters(self):
        apk_name = '0058f6e5225c519df0c0402313061253.apk'
        entry_point = '<com.uniplugin.sender.AReceiver: void onReceive(android.content.Context,android.content.Intent)>'
        result = hasIntentFilters(apk_name,entry_point,'testCases/xml/benign','testCases/xml/malware')
        self.assertEqual(result,'|android.intent.action.BOOT_COMPLETED|android.intent.action.PHONE_STATE|')
    
    def test_identifyenvet(self):
        self.assertEqual(identifyenvet('testCases/testinput.csv','testCases/xml/benign','testCases/xml/malware','testCases'),None)



if __name__ == '__main__':
    unittest.main()