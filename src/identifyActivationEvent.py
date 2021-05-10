import pandas as pd
import os
import codecs
import csv

def processStr(string):
    string = string.replace('<',' ')
    string = string.replace('.',' ')
    string = string.replace(':',' ')
    string = string.replace('(',' ')
    string = string.replace(')',' ')
    string = string.replace('|',' ')
    string = string.replace('>',' ')
    string = string.replace(',',' ')
    return string

def isLifecyle(entrypoint):
    lifecycle=[]
    lifecycle.append('onCreate')
    lifecycle.append('onStart')
    lifecycle.append('onResume')
    lifecycle.append('onPause')
    lifecycle.append('onStop')
    lifecycle.append('onDestroy')
    lifecycle.append('onReceive')
    lifecycle.append('onDestroy')
    for i in lifecycle:
        if i in processStr(entrypoint).split(' '):
            return True
    return False


def isEventHandler(entrypoint):
    eventHandler=[]
    eventHandler.append('onClick')
    eventHandler.append('onLongClick')
    eventHandler.append('onItemClick')
    eventHandler.append('onFocusChange')
    eventHandler.append('onKey')
    eventHandler.append('onTouch')
    eventHandler.append('onCreateContextMenu')
    eventHandler.append('onCheckedchanged')
    eventHandler.append('onItemSelected')
    eventHandler.append('onDataChanged')
    eventHandler.append('onTimeChanged')
    eventHandler.append('onContextItemSelected')
    eventHandler.append('onMenuItemSelected')
    
    eventHandler.append('onKeyDown')
    eventHandler.append('onKeyUp')
    eventHandler.append('onTrackballEvent')
    eventHandler.append('onTouchEvent')
    eventHandler.append('onFocusChanged')
    eventHandler.append('dispatchTouchEvent')
    eventHandler.append('onInterceptTouchEvent')
    eventHandler.append('requestDisallowInterceptTouchEvent')
    for i in eventHandler:
        if i in entrypoint:
            return i
    return

def hasIntentFilters(apk_name, entrypoint,path1,path2):
    # path1 = 'xml/benign'
    # path2 = 'xml/malware'
    for file in os.listdir(path1):
        if apk_name == file:
            file_path = os.path.join(path1, file)
            break
    for file in os.listdir(path2):
        if apk_name == file:
            file_path = os.path.join(path2, file)
            break
    csv_path = os.path.join(file_path, 'out.csv')
    xml = pd.read_csv(csv_path)
    component = xml["component"]
    intent_filter = xml["intent_filter"]
    
    for i, c in enumerate(component):
        if c.split('.')[-1] in entrypoint and intent_filter[i] !='|':
            return intent_filter[i]
    return



def identifyenvet(filename,xml_benign_folder,xml_malware_folder,output_folder):
    apk_name=[]
    permission=[]
    method=[]
    entry_point=[]
    with open(filename) as f:
        reader = csv.reader(f)
        for row in reader:
            apk_name.append(row[0])
            permission.append(row[1])
            method.append(row[2])
            entry_point.append(row[3])
    
    outputfile = filename.split('.')[0].split('/')[1]+'Event.csv'
    outputfile = os.path.join(output_folder,outputfile)

    path1 = xml_benign_folder
    path2 = xml_malware_folder

    with open(outputfile, 'w') as fw:
        writer = csv.writer(fw)
        for i, method_i in enumerate(method):
            activation_event = ''
            if isLifecyle(entry_point[i]):
                if hasIntentFilters(apk_name[i], entry_point[i],path1,path2) is not None:
                    # system event
                    activation_event+=hasIntentFilters(apk_name[i], entry_point[i],path1,path2)
                    activation_event+='|'
                else:
                    # hardware event
                    activation_event+=entry_point[i]
                    activation_event+='|'
            if isEventHandler(entry_point[i]) is not None:
                # UI event
                activation_event+=isEventHandler(entry_point[i])
                activation_event+='|'
            # print(activation_event)
            writer.writerow([apk_name[i],permission[i],method_i,entry_point[i],activation_event])


if __name__ == "__main__":
    inputfile=[]
    inputfile.append('input/DowginOut.csv')
    inputfile.append('input/AirpushOut.csv')
    inputfile.append('input/KuguoOut.csv')
    inputfile.append('input/YoumiOut.csv')
    inputfile.append('input/FakeInstOut.csv')
    inputfile.append('input/benignOut.csv')

    xml_benign_folder = 'xml/benign'
    xml_malware_folder = 'xml/malware'
    for i in inputfile:
        identifyenvet(i,xml_benign_folder,xml_malware_folder,'output')