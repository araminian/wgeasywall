

def generateIPSetScript(IPSetDict):
    
    fileName = '01-WGEasyWall-IPSet.sh'
    with open ( fileName, 'w') as rsh:
        rsh.write('''\
#!/bin/bash
echo "WGEasywall IPSet Generator"
echo "-----------------------------"
''')

    arrayDeleteVariable = "${{{0}{1}}}".format("Sets2deleteArray","[@]")
    with open ( fileName, 'a') as rsh:
        rsh.write('''\
echo "Remove WGEasywall generated IPSets"
echo "-----------------------------"
Sets2delete="$(ipset list | grep 'Name:' | cut -d\  -f2 | grep 'WGEasywall' | tr '\\n' ' ')"
IFS=', ' read -r -a Sets2deleteArray <<< "$Sets2delete"
for set in "{0}"; do
  echo "Remove IPSet $set"
  ipset destroy $set
done
echo "-----------------------------"
'''.format(arrayDeleteVariable))

    for Group,IPs in IPSetDict.items():
        
        Group = Group.replace("::","-")
        arrayName = "{0}_{1}".format(Group,"IPs")
        arrayName = arrayName.replace("-","_")
        arrayVariable = "${{{0}{1}}}".format(arrayName,"[@]")

        IPsBashArray = "{0}=({1})".format(arrayName,' '.join(IPs))

        IPSetName = "WGEasywall-{0}".format(Group)

        with open ( fileName, 'a') as rsh:
            rsh.write('''\
# Group {0}
echo "Create Set {1} ..."
ipset create {1} hash:ip
{2}

for IP in "{3}"; do
  ipset add {1} $IP
done
echo "Set {1} Done"
echo "-----------------------------"
ipset list {1}
echo "-----------------------------"
'''.format(
           Group,
           IPSetName,
           IPsBashArray,
           arrayVariable
        ))




