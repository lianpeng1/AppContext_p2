import os

if __name__ == '__main__':
    os.system('coverage run testCases/disassembleTest.py')
    os.system('coverage report')
    os.system('coverage run testCases/xmlTest.py')
    os.system('coverage report')
    os.system('coverage run testCases/identifyTest.py')
    os.system('coverage report')