import os
import subprocess
# import shutil

def disassemble_apk(frompath, topath):
    files = os.listdir(frompath)
    count = 0
    for dummy_i, file in enumerate(files):
        fullFrompath = os.path.join(frompath, file)
        fullTopath = os.path.join(topath, file)
        command = "apktool d " + fullFrompath + " -o " + fullTopath
        subprocess.call(command, shell=True)
        count = count + 1
    if count == len(files):
        return True
    else:
        return False

def toSmali(apk_path,smali_folder):
    apk_path1=os.path.join(apk_path, "benign")
    apk_path2=os.path.join(apk_path, "Airpush")
    apk_path3=os.path.join(apk_path, "Kuguo")
    apk_path4=os.path.join(apk_path, "Youmi")
    apk_path5=os.path.join(apk_path, "FakeInst")
    apk_path6=os.path.join(apk_path, "Dowgin")

    benign_path = os.path.join(smali_folder,'benign')
    malware_path= os.path.join(smali_folder,'malware')

    if not os.path.exists(benign_path):
        os.makedirs(benign_path)
    if not os.path.exists(malware_path):
        os.makedirs(malware_path)

    disassemble_apk(apk_path1, benign_path)
    disassemble_apk(apk_path2, malware_path)
    disassemble_apk(apk_path3, malware_path)
    disassemble_apk(apk_path4, malware_path)
    disassemble_apk(apk_path5, malware_path)
    disassemble_apk(apk_path6, malware_path)

if __name__ == '__main__':
    toSmali('./apk','smali')