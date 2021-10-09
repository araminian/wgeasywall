from wgeasywall.utils.ruleAsCode.action import generateAction, extractActionDefinition
from wgeasywall.utils.ruleAsCode.function import generateRule, extractFunctionDefinition
import subprocess

def getActionFunctionName(name):

    return name.split('(')[0]

def createRules (function,actionVersion,functionVersion):

    finalRules = []

    functionPart = function.split('->')
    rules , action = functionPart[0] , functionPart[1]

    rulesList = rules.split("::")
    for rule in rulesList:
        func = "{0}::{1}".format(rule,action)
        ruleEnd = generate(func,actionVersion,functionVersion)
        if(type(ruleEnd) == dict):
            return ruleEnd
        finalRules.append(ruleEnd)
        
    return finalRules


def generate(function,actionVersion,functionVersion):

    rulePart = function.split('::')
    function , action = rulePart[0] , rulePart[1]

    actionName = getActionFunctionName(action)
    functionName = getActionFunctionName(function)

    actionDefinition = extractActionDefinition(actionName,actionVersion)
    functionDefinition = extractFunctionDefinition(functionName,functionVersion)

    if(type(actionVersion) == dict and 'ErrorCode' in actionDefinition):
        return actionDefinition
    if(type(functionDefinition) == dict and 'ErrorCode' in functionDefinition):
        return functionDefinition

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