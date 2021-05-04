import os
import subprocess
# import shutil

def disassemble(frompath, topath):
    files = os.listdir(frompath)
    for i, file in enumerate(files):
        fullFrompath = os.path.join(frompath, file)
        fullTopath = os.path.join(topath, file)
        command = "apktool d " + fullFrompath + " -o " + fullTopath
        subprocess.call(command, shell=True)
def toSmali(apk_path):
    apk_path1=os.path.join(apk_path, "benign")
    apk_path2=os.path.join(apk_path, "Airpush")
    apk_path3=os.path.join(apk_path, "Kuguo")
    apk_path4=os.path.join(apk_path, "Youmi")
    apk_path2=os.path.join(apk_path, "FakeInst")

    benign_path = "smali/benign"
    malware_path="smali/malware"

    if not os.path.exists(benign_path):
        os.makedirs(benign_path)
    if not os.path.exists(malware_path):
        os.makedirs(malware_path)

    disassemble(apk_path1, benign_path)
    disassemble(apk_path2, malware_path)
    disassemble(apk_path3, malware_path)
    disassemble(apk_path4, malware_path)

if __name__ == '__main__':
    toSmali('./apk')