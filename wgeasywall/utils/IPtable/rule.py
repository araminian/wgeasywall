def dnsLookUP(domain):
    import socket
    result = socket.gethostbyname_ex(domain)
    return (result[2])
    
def generateRaaC(actionList,functionArgs,functionName='General'):

    functionArgumentsConcat = ':'.join(functionArgs)
    functionSyntax = "{0}({1})".format(functionName,functionArgumentsConcat)

    RaaCList = []

    for action in actionList:
        RaaC = "{0}->{1}".format(functionSyntax,action)
        RaaCList.append(RaaC)
    
    return RaaCList


def generateActionSyntax(graph,edgeID,edgeName,mode,blacklistAction,defaultAction=None):

    srcEdgeID = edgeID[0]
    dstEdgeID = edgeID[1]

    srcEdgeName = edgeName[0]
    dstEdgeName = edgeName[1]

    edgeAttributes = graph.get_edge_data(srcEdgeID,dstEdgeID)
    if ('Action' not in edgeAttributes and defaultAction==None):
        return {"ErrorCode":"321","ErrorMsg":"Not Defined action for edge {0} -> {1}".format(srcEdgeName,dstEdgeName)}
    action = edgeAttributes['Action'].split(',')
    preDefinedActions = ['ACCEPT()','DROP()']
    moreActionFlag = False
    for act in preDefinedActions:
        if (act in action and moreActionFlag):
            return {"ErrorCode":"322","ErrorMsg":"Uncompatible actions {2} for edge {0} -> {1}".format(srcEdgeName,dstEdgeName,action)}
        elif (act in action):
            moreActionFlag = True
    
    action2Return = []
    if(mode=='Smart'):
        return action
    for act in action:
        if(mode=='Blacklist'):
            if('ACCEPT' in act):
                action2Return.append("{0}()".format(blacklistAction))
            elif('LOG' in act):
                action2Return.append(act)
            else:
                action2Return.append(act)
        elif(mode=='Whitelist'):
            if('DROP' in act or 'REJECT' in act):
                action2Return.append('ACCEPT()')
            elif('LOG' in act):
                action2Return.append(act)
            else:
                action2Return.append(act)
    return action2Return

def generateFunctionSyntax(graph,edgeID,edgeName):

    srcEdgeID = edgeID[0]
    dstEdgeID = edgeID[1]
    srcType = edgeID[3]
    dstType = edgeID[4]

    srcEdgeName = edgeName[0]
    dstEdgeName = edgeName[1]

    edgeAttributes = graph.get_edge_data(srcEdgeID,dstEdgeID)

    functionArguments = []

    # Protocol
    if('Protocol' not in edgeAttributes):
        functionArguments.append("protocol=tcp")
    else:
        if(edgeAttributes['Protocol'].lower() not in ['tcp','udp']):
            return {"ErrorCode":"320","ErrorMsg":"Unknown protocol {0} for edge {1} -> {2}".format(edgeAttributes['Protocol'],srcEdgeName,dstEdgeName)}
            
        functionArguments.append("protocol={0}".format(edgeAttributes['Protocol'].lower()))

    # IPs or Set
    
    ## Src
    if (srcType=='Group'):
        srcSetName = srcEdgeName.replace("::","-")
        functionArguments.append("srcSet=WGEasywall-{0}".format(srcSetName))
    elif(srcType=='Node'):
        functionArguments.append("srcIP={0}".format(graph.nodes[srcEdgeID]['IPAddress']))
    elif(srcType=='Server'):
        pass
    elif(srcType=='Resource'):
        resource = graph.nodes[srcEdgeID]
        if ('Hostname' in resource and resource['Hostname'] != 'NULL'):
            lookedUPIP = dnsLookUP(resource['Hostname'])
            IPforRule = ','.join(lookedUPIP)
            functionArguments.append("srcIP={0}".format(IPforRule))
        elif('IPAddress' in resource):
            functionArguments.append("srcIP={0}".format(resource['IPAddress']))

    # TODO: Network Resource Type
    ## Dst
    if (dstType=='Group'):
        dstSetName = dstEdgeName.replace("::","-")
        functionArguments.append("dstSet=WGEasywall-{0}".format(dstSetName))
    elif(dstType=='Node'):
        functionArguments.append("dstIP={0}".format(graph.nodes[dstEdgeID]['IPAddress']))
    elif(dstType=='Server'):
        pass
    elif(dstType=='Resource'):
        resource = graph.nodes[dstEdgeID]
        if ('Hostname' in resource and resource['Hostname'] != 'NULL'):
            lookedUPIP = dnsLookUP(resource['Hostname'])
            IPforRule = ','.join(lookedUPIP)
            functionArguments.append("dstIP={0}".format(IPforRule))
        elif('IPAddress' in resource):
            functionArguments.append("dstIP={0}".format(resource['IPAddress']))

    # Ports
    ## Src
    if ('SrcPorts' in edgeAttributes):
        srcPorts = edgeAttributes['SrcPorts']
        functionArguments.append("srcPorts={0}".format(srcPorts))
    if ('DstPorts' in edgeAttributes):
        dstPorts = edgeAttributes['DstPorts']
        functionArguments.append("dstPorts={0}".format(dstPorts))
    
    # Comment
    comment= "WGEasywall generated rule for edge from {0} to {1}".format(srcEdgeName.replace("::","-"),dstEdgeName.replace("::","-"))
    functionArguments.append("comment='{0}'".format(comment))
    return functionArguments
