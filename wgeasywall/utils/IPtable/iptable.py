def generateIPTableScript(IPTableRules,DefaultAction='DROP',AppendMode=False,ReturnMode=False,Mode='Smart'):

    fileName = '02-WGEasyWall-IPTable.sh'
    with open ( fileName, 'w') as rsh:
        rsh.write('''\
#!/bin/bash
echo "WGEasywall IPTable Rules Importer"
echo "-----------------------------"
''')


    chainName='WGEasywall'
    chainSyntax = "iptables -A {0}".format(chainName)
    with open ( fileName, 'a') as rsh:
        rsh.write('''\
chainName={0}
if iptables -L $chainName 2 > /dev/null 2>&1; then
  echo "The chain '{0}' exist"
  echo "Start fulshing ...."
  iptables -F $chainName
  iptables -D FORWARD -j $chainName
  echo "Flushing done"
  echo "-----------------------------"
else
  echo "The chain '{0}' doesn't exist. Let's create ..."
  iptables -N $chainName
  echo "The chain '{0}' is created"
  echo "-----------------------------"
fi
'''.format(
    chainName
))
    with open ( fileName, 'a') as rsh:
        for iRule in IPTableRules:
            IPTaleRule = "{0} {1}".format(chainSyntax,iRule[1])
            rsh.write('''\
# RaaC definition:
# {0}                
{1}
#---------------------------
'''.format(iRule[0],IPTaleRule))

    with open ( fileName, 'a') as rsh:
        if(not AppendMode):
          rsh.write('''\
            
# AppendMode is not enabled. Update FORWARD chain to use {0} chain
iptables -I FORWARD 1 -j {0}
'''.format(chainName))
        else:
          rsh.write('''\

# AppendMode is enabled. Update FORWARD chain to use {0} chain
iptables -A FORWARD -j {0}
'''.format(chainName))

    with open ( fileName, 'a') as rsh:
        if (not ReturnMode):
          rsh.write('''\

# ReturnMode is not enabled. Default chain policy is {1}            
{0} -j {1}
    '''.format(
        chainSyntax,DefaultAction
    ))
        if (ReturnMode):
            rsh.write('''\

# ReturnMode is enabled. Return to FORWARD chain
iptables -A {0} -j RETURN     
'''.format(chainName))



