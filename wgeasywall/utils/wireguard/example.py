import wgeasywall.utils.wireguard.models as wg_models
from wgeasywall.utils.wireguard.generator import *

ServerInterface =  wg_models.InterfaceModel (
    PrivateKey = wg_models.KeyModel(Key="yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="),
    ListenPort = 51820,
    CommentKey = "Interface" ,
    CommentValue = "WG0",
    Address = "192.168.0.1/24"
)

peer1forServer = wg_models.PeerModel(
    PublicKey = wg_models.KeyModel(Key="yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="),
    AllowedIPs = ["192.168.0.2/32"],
    # Endpoint = wg_models.EndpointModel (
    #     Address = "10.100.10.40",
    #     Port = 123
    # ),
    CommentKey = "User" , 
    CommentValue = "ARMIN"
)

peer2forServer = wg_models.PeerModel(
    PublicKey = wg_models.KeyModel(Key="yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="),
    AllowedIPs = ["192.168.0.3/32"],
    # Endpoint = wg_models.EndpointModel (
    #     Address = "10.100.10.40",
    #     Port = 123
    # ),
    CommentKey = "User" , 
    CommentValue = "Jack"
)

peers = []
peers.append(generate_peer(peer1forServer))
peers.append(generate_peer(peer2forServer))

configComponents = wg_models.ConfigComponentsModel(
    Interface = generate_interface(ServerInterface),
    Peers = peers,
    ConfigPath = '/home/armin/wg/wg-new.conf'
)

generate_wg_conf_file(configComponents)


# peer

peer1Interface = wg_models.InterfaceModel (
    PrivateKey = wg_models.KeyModel(Key="yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="),
    ListenPort = 51820,
    CommentKey = "Interface" ,
    CommentValue = "WG0",
    Address = "192.168.0.2/32"
)

serverAsPeer = wg_models.PeerModel(
    PublicKey = wg_models.KeyModel(Key="yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="),
    AllowedIPs = ["0.0.0.0/0"],
    Endpoint = wg_models.EndpointModel (
         Address = "10.100.10.40",
         Port = 51820
     ),
    CommentKey = "User" , 
    CommentValue = "Server"
)

serverPeer = []
serverPeer.append(generate_peer(serverAsPeer))
configComponentsPeer1 = wg_models.ConfigComponentsModel(
    Interface = generate_interface(peer1Interface),
    Peers = serverPeer,
    ConfigPath = '/home/armin/wg/wg-peer1.conf'
)

generate_wg_conf_file(configComponentsPeer1)
