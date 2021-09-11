import donna25519, base64


def generateEDKeyPairs():

    """A function which generates ED25519 key pairs"""

    privateKey = donna25519.PrivateKey()

    pvKey = privateKey.private
    pbKey = privateKey.get_public().public

    return (base64.b64encode(pvKey).decode(),base64.b64encode(pbKey).decode())