import codecs
from xml.etree.ElementTree import parse

namespace = '{http://schemas.android.com/apk/res/android}'
source_filePath = r'test/AndroidManifest.xml'
output_file_path = r'test/xml.csv'

if __name__ == "__main__":
    tree = parse(source_filePath)
    root = tree.getroot()
    packagename = root.attrib["package"]
    application = root.find("application")
    
    fw = codecs.open(output_file_path, 'w', 'utf-8')
    fw.write("component,intent_filter\n")
    for component in application:
        attribute='|'
        component_name = component.attrib[namespace+'name']
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