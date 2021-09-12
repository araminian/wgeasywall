from deepdiff import DeepDiff, diff
import re, copy

def parsePath(path):
    return (re.findall("\[(.*?)\]", path))

def getWGNetSettings(netDict):
    tempNetDict = copy.deepcopy(netDict)
    
    WGNet = tempNetDict['WGNet']
    del WGNet['Server']
    del WGNet['Clients']
    return WGNet

def getNetworkResource(netDict):
    return netDict['NetworkResources']

# Net,Server,Clients,NetworkResources
def getWGNetSection(section,netDict):
    if (section == 'Net'):
        return getWGNetSettings(netDict)
    if (section == 'NetworkResources'):
        return getNetworkResource(netDict)
    return netDict['WGNet'][section] #Sever,Clients

def parseDdif(diffDict,objectType,netName):

    diffParsedDict = {}

    iterItemRemovedDict = {}
    iterItemRemovedDict['Description'] = "These Items are removed from the new Network Definition"
    iterItemRemovedDict['ObjectType'] = objectType
    iterItemRemovedDict['Items'] = []

    dictItemAddedDict = {}
    dictItemAddedDict['Description'] = "These new attributes are added to the objects"
    dictItemAddedDict['ObjectType'] = objectType
    dictItemAddedDict['Items'] = []


    iterItemAddedDict = {}
    iterItemAddedDict['Description'] = "These items are added to the new Network Definition"
    iterItemAddedDict['ObjectType'] = objectType
    iterItemAddedDict['Items'] = []

    dictItemRemovedDict = {}
    dictItemRemovedDict['Description'] = "These attributes are removed from the objects"
    dictItemRemovedDict['ObjectType'] = objectType
    dictItemRemovedDict['Items'] = []

    valuesChangedDict = {}
    valuesChangedDict['Description'] = "Value of attributes of these objects are changed to new values"
    valuesChangedDict['ObjectType'] = objectType
    valuesChangedDict['Items'] = []
    
    for diffType in diffDict:

        if (diffType == 'dictionary_item_removed'):
            
            for diff in diffDict[diffType]:
                
                # Case where the one item is removed and one item is added , deepdiff detects it as value_changed (rename)
                if (diff.up.t1['Name'] != diff.up.t2['Name']):
                    continue
                
                objectDict = {}
                objectName = diff.up.t1['Name']
                attributeRemoved= parsePath(diff.path())[-1].replace("'", '')
                objectOldInfo = diff.up.t1
                objectNewInfo = diff.up.t2
                
                objectDict['ObjectName'] = objectName
                objectDict['AttributeRemoved'] = attributeRemoved
                objectDict['NetworkName'] = netName
                objectDict['ObjectOldInfo'] = objectOldInfo
                objectDict['ObjectNewInfo'] = objectNewInfo
                dictItemRemovedDict['Items'].append(objectDict)

        if (diffType == 'iterable_item_added'):
            

            for diff in diffDict[diffType]:
                objectDict = {}
                
                if(objectType == 'Groups'):
                    objectName = diff.t2
                else:
                    objectName = diff.t2['Name']
                objectInfo = diff.t2

                objectDict['ObjectName'] = objectName
                objectDict['NetworkName'] = netName
                objectDict['ObjectInfo'] = objectInfo
                
                iterItemAddedDict['Items'].append(objectDict)

        if (diffType == 'dictionary_item_added'):

            for diff in diffDict[diffType]:
                objectDict = {}
                objectName=diff.up.t2['Name']
                objectOldInfo = diff.up.t1
                objectNewInfo = diff.up.t2
                attributeAdded= parsePath(diff.path())[-1].replace("'", '')

                objectDict['ObjectName'] = objectName
                objectDict['NetworkName'] = netName
                objectDict['AttributeAdded'] = attributeAdded
                objectDict['ObjectOldInfo'] = objectOldInfo
                objectDict['ObjectNewInfo'] = objectNewInfo
                dictItemAddedDict['Items'].append(objectDict)


        if (diffType == 'iterable_item_removed'):
            

            for diff in diffDict[diffType]:
                objectDict = {}
                
                if(objectType == 'Groups'):
                    objectName = diff.t1
                else:
                    objectName = diff.t1['Name']
                objectInfo = diff.t1
                objectDict['ObjectName'] = objectName
                objectDict['NetworkName'] = netName
                objectDict['ObjectInfo'] = objectInfo
                iterItemRemovedDict['Items'].append(objectDict)

        if (diffType == 'values_changed'):
            
            # a List which tracks the object that are checked
            objectChecked = []

            for diff in diffDict[diffType]:

                # If the Name of the Object are changed we consider it as new object,Delete Object Detection,or Whole Object Renames
                if (diff.up.t1['Name'] != diff.up.t2['Name']):

                    if( diff.up.t1 in objectChecked):
                        continue
                    objectChecked.append(diff.up.t1)
                    
                    objectDictAdded = {}
                    objectDictRemoved = {}

                    objectAddedName = diff.up.t2['Name']
                    objectRemovedName = diff.up.t1['Name']

                    objectAddedInfo = diff.up.t2
                    objectRemovedInfo = diff.up.t1

                    objectDictRemoved['ObjectName'] = objectRemovedName
                    objectDictRemoved['NetworkName'] = netName
                    objectDictRemoved['ObjectInfo'] = objectRemovedInfo

                    objectDictAdded['ObjectName'] = objectAddedName
                    objectDictAdded['NetworkName'] = netName
                    objectDictAdded['ObjectInfo'] = objectAddedInfo

                    iterItemRemovedDict['Items'].append(objectDictRemoved)
                    iterItemAddedDict['Items'].append(objectDictAdded)
                else:
                    attributeValueChanged = parsePath(diff.path())[-1].replace("'", '')
                    objectDict = {}
                    objectName = diff.up.t2['Name']
                    objectOldInfo = diff.up.t1
                    objectNewInfo = diff.up.t2
                    
                    objectDict['ObjectName'] = objectName
                    objectDict['NetworkName'] = netName
                    objectDict['ObjectOldInfo'] = objectOldInfo
                    objectDict['ObjectNewInfo'] = objectNewInfo
                    objectDict['AttributeChanged'] = attributeValueChanged

                    valuesChangedDict['Items'].append(objectDict)


    diffParsedDict['iterable_item_removed'] = iterItemRemovedDict
    diffParsedDict['dictionary_item_added'] = dictItemAddedDict
    diffParsedDict['iterable_item_added'] = iterItemAddedDict
    diffParsedDict['dictionary_item_removed'] = dictItemRemovedDict
    diffParsedDict['values_changed'] = valuesChangedDict
    return diffParsedDict

def getNetDiff(newNetDict,oldNetDict,netName,section):
    
    newObjects = getWGNetSection(section,newNetDict)
    oldObjects = getWGNetSection(section,oldNetDict)

    ddiff = DeepDiff(oldObjects, newObjects, ignore_order=True,view='tree')

    return parseDdif(ddiff,section,netName)

def detectGroupTransfer(diffData):

    desireItem = []

    changedItem = diffData['values_changed']
    for item in changedItem['Items']:
        objectInfo = {}
        if item['AttributeChanged'] == 'Group':
            objectInfo['Name'] = item['ObjectNewInfo']['Name']
            objectInfo['NetworkName'] = item['NetworkName']
            objectInfo['OldGroup'] = item['ObjectOldInfo']['Group']
            objectInfo['NewGroup'] = item['ObjectNewInfo']['Group']
        desireItem.append(objectInfo)
    return desireItem


def detectGroupRemove(diffData):

    desireItems = []

    removedItem = diffData['dictionary_item_removed']
    for item in removedItem['Items']:
        objectInfo = {}
        if item['AttributeRemoved'] == 'Group':
            objectInfo['Name'] = item['ObjectNewInfo']['Name']
            objectInfo['NetworkName'] = item['NetworkName']
            objectInfo['Group'] = item['ObjectOldInfo']['Group']
        desireItems.append(objectInfo)
    return desireItems

def detectGroupAdd (diffData):

    desireItems = []

    addedItem = diffData['dictionary_item_added']

    for item in addedItem['Items']:
        objectInfo = {}
        if item['AttributeAdded'] == 'Group':
            objectInfo['Name'] = item['ObjectNewInfo']['Name']
            objectInfo['NetworkName'] = item['NetworkName']
            objectInfo['Group'] = item['ObjectNewInfo']['Group']
        desireItems.append(objectInfo)
    return desireItems

def detectRemovedItem(diffData):

    removedItems = diffData['iterable_item_removed']
    return removedItems['Items']



# Graph = readGraphML('network-newG.graphml')
# newNetDef = readYAML(filename='net-new.yaml')
# oldNetDef = readYAML(filename='net-old.yaml')

# networkName = newNetDef['WGNet']['Name']

# diffClients = getNetDiff(newNetDef,oldNetDef,networkName,'Clients')
