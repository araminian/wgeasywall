from os import error
from sys import argv
from networkx.readwrite.edgelist import parse_edgelist
import typer
from pathlib import Path
import networkx as nx
import wgeasywall.utils.graphml.parser as parser
from wgeasywall.utils.IPtable.ipset import generateIPSetScript
from wgeasywall.utils.IPtable.score import getScore
from wgeasywall.utils.IPtable.rule import dnsLookUP, generateActionSyntax, generateFunctionSyntax, generateRaaC
from wgeasywall.utils.ruleAsCode.generate import createRules, migrateToNFT
from wgeasywall.utils.IPtable.iptable import generateIPTableScript
app = typer.Typer()

@app.command()
def generate(
    graphFile: Path = typer.Option(...,"--graph-file",help="The GraphML file"),
    AppendMode: bool = typer.Option(False,"--append-mode",help="IF 'Enabled' the WGEasywall chain will be inserted at the first of FORWARD chain. IF not it will be added at the end"),
    ReturnMode: bool = typer.Option(False,"--return-mode",help="IF 'Enabled' if there is no rule match for packets, the packets don't back to FORWARD chain and will be matched with 'default-chain-policy'"),
    DefaultChainPolicy: str = typer.Option("DROP","--default-chain-policy",help="The default policy for WGEasywall chain which be useful if the 'Return mode' is disabled")
):
    if not graphFile.is_file():
        typer.echo("ERROR: GraphML file can't be found!",err=True)
        raise typer.Exit(code=1)
    nft = False
    # Parse graph
    graph = nx.read_graphml(graphFile)
    groups = parser.findGroup(graph)

    # Get all edges
    allEdges = parser.getAllEdgesList(graph)

    # Maps
    clientsMapName2ID = parser.mapClientsIDName(graph)
    groupsMapName2ID = parser.mapGroupsIDName(graph,groups)
    networkResourceMapName2ID = parser.mapNetResourcesIDName(graph)

    clientsMapID2Name = dict((v,k) for k,v in clientsMapName2ID.items())
    groupsMapID2Name = dict((v,k) for k,v in groupsMapName2ID.items())
    networkResourceMapID2Name = dict((v,k) for k,v in networkResourceMapName2ID.items())

    # Create IPSet
    createdIPSet = {}
    for edge in allEdges:

        srcEdgeID = edge[0]
        dstEdgeID = edge[1]
        
        
        # Check if  the src or dst are group
        if (srcEdgeID in groupsMapID2Name):
            srcEdgeName = groupsMapID2Name[srcEdgeID]
            if (srcEdgeName not in createdIPSet):
                nodesOfSrcGroup = parser.getNodesInGroup(graph,srcEdgeID,groups)

                IPsInIPSet = []
                for node in nodesOfSrcGroup:
                    IPsInIPSet.append(str(graph.nodes[node]['IPAddress']))
                createdIPSet[srcEdgeName] = IPsInIPSet
        if (dstEdgeID in groupsMapID2Name):
            dstEdgeName = groupsMapID2Name[dstEdgeID]
            if (dstEdgeName not in createdIPSet):
                nodesOfDstGroup = parser.getNodesInGroup(graph,dstEdgeID,groups)
                
                IPsInIPSet = []
                for node in nodesOfDstGroup:
                    IPsInIPSet.append(str(graph.nodes[node]['IPAddress']))
                createdIPSet[dstEdgeName] = IPsInIPSet

    generateIPSetScript(createdIPSet)     
    
    edgeScoreID , edgeScoreName = getScore(allEdges,clientsMapID2Name,groupsMapID2Name,networkResourceMapID2Name)
    IPtableRules = []
    for edge in edgeScoreID:
        index = edgeScoreID.index(edge)
        edgeN = edgeScoreName[index]
        srcEdgeName = edgeN[0]
        dstEdgeName = edgeN[1]
        # Get Attributes of a edge to determine use normal way or special RaaC
        srcEdgeID = edge[0]
        dstEdgeID = edge[1]
        srcType = edge[3]
        dstType = edge[4]
        edgeAttributes = graph.get_edge_data(srcEdgeID,dstEdgeID)
        # Special way 
        if ('RaaC' in edgeAttributes):
            specialRaaCs = edgeAttributes['RaaC'].split(',')
            argumentsToInject = {}
            if(srcType == 'Group'):
                srcSetName = srcEdgeName.replace("::","-")
                argumentsToInject['srcSet'] = "WGEasywall-{0}".format(srcSetName)
            elif(srcType=='Node'):
                argumentsToInject['srcIP'] = graph.nodes[srcEdgeID]['IPAddress']
            elif(srcType=='Resource'):
                resource = graph.nodes[srcEdgeID]
                if ('Hostname' in resource and resource['Hostname'] != 'NULL'):
                    lookedUPIP = dnsLookUP(resource['Hostname'])
                    IPforRule = ','.join(lookedUPIP)
                    argumentsToInject['srcIP']=IPforRule
                elif('IPAddress' in resource):
                    argumentsToInject['srcIP']=resource['IPAddress']

            if (dstType == 'Group'):
                dstSetName = dstEdgeName.replace("::","-")
                argumentsToInject['dstSet'] = "WGEasywall-{0}".format(dstSetName)
            elif(dstType == 'Node'):
                argumentsToInject['dstIP'] = graph.nodes[dstEdgeID]['IPAddress']
            elif(dstType=='Resource'):
                resource = graph.nodes[dstEdgeID]
                if ('Hostname' in resource and resource['Hostname'] != 'NULL'):
                    lookedUPIP = dnsLookUP(resource['Hostname'])
                    IPforRule = ','.join(lookedUPIP)
                    argumentsToInject['dstIP']=IPforRule
                elif('IPAddress' in resource):
                    argumentsToInject['dstIP']=resource['IPAddress']

            comment= "WGEasywall generated rule for edge from {0} to {1}".format(srcEdgeName.replace("::","-"),dstEdgeName.replace("::","-"))
            argumentsToInject['comment'] = "'{0}'".format(comment)

            for sRaaC in specialRaaCs:

                ruleEnd = createRules(
            function=sRaaC,
            actionVersion='@latest',
            functionVersion='@latest',
            injectArgumets=argumentsToInject
            )

                if (type(ruleEnd) == dict):
                    typer.echo("The following RaaC defnition can't be translated to IPTable rules:\n{0}\nReason: {1}".format(sRaaC,ruleEnd['ErrorMsg']))
                    continue
                
                for rule in ruleEnd:
                    rule2show = ' '.join(rule)
                    if (not nft):
                        IPtableRules.append((sRaaC,rule2show))
                    else:
                        nftRule = migrateToNFT(rule2show)
                        nftRuleComponents = nftRule.split(" ")
                        desiredIndex = nftRuleComponents.index("FORWARD")
                        IPtableRules.append((sRaaC,' '.join(nftRuleComponents[desiredIndex+1:])))
            continue
        
        # Normal Way
        functionArgument = generateFunctionSyntax(graph,edge,edgeN)
        
        actionList = generateActionSyntax(graph,edge,edgeN)
        

        errorFlag = False
        if (type(actionList) == dict and 'ErrorCode' in actionList):
            errorFlag = True
            typer.echo("ERROR: Edge '{0}' to '{1}'. Reason: '{2}'\n".format(srcEdgeName,dstEdgeName,actionList['ErrorMsg']))
        if (type(functionArgument) == dict and 'ErrorCode' in functionArgument):
            typer.echo("ERROR: Edge '{0}' to '{1}'. Reason: '{2}'\n".format(srcEdgeName,dstEdgeName,functionArgument['ErrorMsg']))
            errorFlag = True

        if (errorFlag):
            continue

        RaaCList = generateRaaC(actionList,functionArgument)
                
        for generatedRule in RaaCList:

            ruleEnd = createRules(
            function=generatedRule,
            actionVersion='@latest',
            functionVersion='@latest'
            )

            if (type(ruleEnd) == dict):
                IPtableRules.append((generatedRule,ruleEnd['ErrorMsg']))
    
            for rule in ruleEnd:
                rule2show = ' '.join(rule)
                if (not nft):
                    IPtableRules.append((generatedRule,rule2show))
                else:
                    nftRule = migrateToNFT(rule2show)
                    nftRuleComponents = nftRule.split(" ")
                    desiredIndex = nftRuleComponents.index("FORWARD")
                    IPtableRules.append((generatedRule,' '.join(nftRuleComponents[desiredIndex+1:])))
        
    for iRule in IPtableRules:
        print(iRule[0])
        print()
        print(iRule[1])
        print("-------------------")
    generateIPTableScript(IPtableRules,AppendMode=AppendMode,ReturnMode=ReturnMode,DefaultAction=DefaultChainPolicy)
