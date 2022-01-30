from wgeasywall.utils.ruleAsCode.action import generateAction, extractActionDefinition
from wgeasywall.utils.ruleAsCode.function import generateRule, extractFunctionDefinition, getFunctionBody
import subprocess

def Inject(functionDefiDict,function,argument,argumentValue):

    functionDefiArgument = functionDefiDict['Func']['Body']['Arguments']
    
    if ( argument in functionDefiArgument):
         
        functionBody=getFunctionBody(function)
        # TODO: in ANY PRoblem here should be checked
        functionName = getActionFunctionName(function)
        if(functionBody == None):
            newFunctionBody= "{0}={1}".format(argument,argumentValue)
        else:
            newFunctionBody= "{0}:{1}={2}".format(functionBody,argument,argumentValue)
        
        newFunction = "{0}({1})".format(functionName,newFunctionBody)
        return newFunction
    else:
        return function

def getActionFunctionName(name):

    return name.split('(')[0]

def createRules (function,actionVersion,functionVersion,injectArgumets=None):

    finalRules = []

    functionPart = function.split('->')
    rules , action = functionPart[0] , functionPart[1]

    rulesList = rules.split("::")
    for rule in rulesList:
        func = "{0}::{1}".format(rule,action)
        ruleEnd = generate(func,actionVersion,functionVersion,injectArgumets=injectArgumets)
        if(type(ruleEnd) == dict):
            return ruleEnd
        finalRules.append(ruleEnd)
        
    return finalRules


def generate(RaaC,actionVersion,functionVersion,injectArgumets=None):

    rulePart = RaaC.split('::')
    function , action = rulePart[0] , rulePart[1]

    actionName = getActionFunctionName(action)
    functionName = getActionFunctionName(function)

    actionDefinition = extractActionDefinition(actionName,actionVersion)
    functionDefinition = extractFunctionDefinition(functionName,functionVersion)

    if(type(actionVersion) == dict and 'ErrorCode' in actionDefinition):
        return actionDefinition
    if(type(functionDefinition) == dict and 'ErrorCode' in functionDefinition):
        return functionDefinition
    
    # Inject some arguments into the function
    
    if (injectArgumets != None):
        for argument,value in injectArgumets.items():
            function = Inject(functionDefinition,function,argument,value)
    
    actionPart = generateAction(action,actionDefinition)
    functionPart = generateRule(function,functionDefinition)

    if(type(actionPart) == dict):
        return actionPart
    if(type(functionPart) == dict):
        return functionPart

    ruleEnd = functionPart + actionPart
    return ruleEnd

def migrateToNFT(rule,tableChain='FORWARD',method='-A'):

    finalRule = tableChain + " " + rule
    command = 'iptables-translate {0} {1}'.format(method,finalRule)
    nftRule = subprocess.run(command,stdout=subprocess.PIPE,text=True,shell=True)

    if(nftRule.returncode != 0 ):
        return {"ErrorCode":"303","ErrorMsg":"Failed to translate IPTable rule to NFT rule"}
    
    return nftRule.stdout