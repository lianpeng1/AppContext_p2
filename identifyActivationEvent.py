import pandas as pd
import codecs

def isLifecyle(string):
    lifecycle=[]
    lifecycle.append('onCreate')
    lifecycle.append('onStart')
    lifecycle.append('onResume')
    lifecycle.append('onPause')
    lifecycle.append('onStop')
    lifecycle.append('onDestroy')
    for i in lifecycle:
        if string == i:
            return True
    return False


# def hasIntentFilters(entry_point):
#     string=[]
#     flag = False
#     return flag, stirng

# def findICC(entry_point):

def isEventHandler(string):
    eventHandler=[]
    eventHandler.append('onClick')
    eventHandler.append('onLongClick')
    eventHandler.append('onFocusChange')
    eventHandler.append('onKey')
    eventHandler.append('onTouch')
    eventHandler.append('onCreateContextMenu')
    
    eventHandler.append('onKeyDown')
    eventHandler.append('onKeyUp')
    eventHandler.append('onTrackballEvent')
    eventHandler.append('onTouchEvent')
    eventHandler.append('onFocusChanged')
    eventHandler.append('dispatchTouchEvent')
    eventHandler.append('onInterceptTouchEvent')
    eventHandler.append('requestDisallowInterceptTouchEvent')
    for i in eventHandler:
        if string == i:
            return True
            return False


origin = pd.read_csv("test/output1.csv")

entrypoint = origin["entry_point"]
method_name = origin["sensitive_method_name"]

path = "test/output2.csv"
fw = codecs.open(path, 'w', 'utf-8')
fw.write("sensitive_method_name,entry_point,activation_event\n")
for i in range(len(entrypoint)):
    activation_events=[]
    if isLifecyle(entrypoint[i].split('.')[1]):
        activation_event=entrypoint[i].split('.')[1]
    if isEventHandler(entrypoint[i].split('.')[1]):
        activation_event=entrypoint[i].split('.')[1]
    else:
        activation_event=entrypoint[i].split('.')[1]
    fw.write("".join([method_name[i], ",", entrypoint[i], ",", activation_event,  "\n"]))