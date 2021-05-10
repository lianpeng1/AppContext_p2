import codecs
import os
from xml.etree.ElementTree import parse

namespace ='{http://schemas.android.com/apk/res/android}'


def xmltocsv(source_filePath,output_file_path):
    try:
        tree = parse(source_filePath)
        root = tree.getroot()
    except Exception:
        print("Excetion"+ source_filePath)
        return False
    dummy_packagename = root.attrib["package"]
    application = root.find("application")
    
    fw = codecs.open(output_file_path, 'w', 'utf-8')
    fw.write("component,intent_filter\n")
    for component in application:
        attribute='|'
        try:
            component_name = component.attrib[namespace+'name']
        except Exception:
            print("Exception"+source_filePath)
            return False
        intent_filter = component.find("intent-filter")
        if intent_filter is not None:
            actionlist = intent_filter.findall('action')
            categorylist = intent_filter.findall('category')
            for action in actionlist:
                if action is not None:
                    attribute = attribute + action.attrib[namespace + "name"] + '|'
            for category in categorylist:
                if category is not None:
                    attribute = attribute + category.attrib[namespace + "name"] + '|'
        fw.write("".join([component_name, ",", attribute,  "\n"]))
    fw.close()
    return True


def findxml(smali_path,benign_path,malware_path):
    smali_path1=os.path.join(smali_path, "benign")
    smali_path2=os.path.join(smali_path, "malware")
    
    if not os.path.exists(benign_path):
        os.makedirs(benign_path)
    if not os.path.exists(malware_path):
        os.makedirs(malware_path)
    
    folders = os.listdir(smali_path1)
    for folder in folders:
        if folder != '.DS_Store':
            folder_path = os.path.join(smali_path1, folder)
            files = os.listdir(folder_path)
            for cur_file in files:
                if cur_file == "AndroidManifest.xml":
                    cur_file_path = os.path.join(folder_path, cur_file)
                    fullTopath = os.path.join(benign_path, folder)
                    if not os.path.exists(fullTopath):
                        os.makedirs(fullTopath)
                    fullTopath = os.path.join(fullTopath, "out.csv")
                    xmltocsv(cur_file_path, fullTopath)
    folders = os.listdir(smali_path2)
    for folder in folders:
        if folder != '.DS_Store':
            folder_path = os.path.join(smali_path2, folder)
            files = os.listdir(folder_path)
            for cur_file in files:
                if cur_file == "AndroidManifest.xml":
                    cur_file_path = os.path.join(folder_path, cur_file)
                    fullTopath = os.path.join(malware_path, folder)
                    if not os.path.exists(fullTopath):
                        os.makedirs(fullTopath)
                    fullTopath = os.path.join(fullTopath, "out.csv")
                    xmltocsv(cur_file_path, fullTopath)


if __name__ == "__main__":
    benign_path = "xml/benign"
    malware_path= "xml/malware"
    findxml("./smali",benign_path,malware_path)
