python3 main.py config generate database --mongodb-address 127.0.0.1 --mongodb-user armin --mongodb-password testtest

python3 main.py network initilize --network-file net-sample.yaml --keys-dir /home/armin/Thesis/WireGuard-Config-Generator/wgeasywall/keysdir
python3 main.py wireguard generate --network-name WGNet1 --all

python3 main.py wireguard key-generate --all --network-name WGNet1 --keys-dir /home/armin/Thesis/WireGuard-Config-Generator/wgeasywall/keysdir

# ALL Change
python3 main.py wireguard key-generate --all --network-name WGNet1 --keys-dir /home/armin/Thesis/WireGuard-Config-Generator/wgeasywall/keysdir --output-dir /home/armin/wgconf

# Only Server
python3 main.py wireguard key-generate --network-name WGNet1 --server --output-dir /home/armin/wgconf  

# Only two clients
python3 main.py wireguard key-generate --network-name WGNet1 --clients-list Client1,Client3 --output-dir /home/armin/wgconf

# All Clients
python3 main.py wireguard key-generate --network-name WGNet1 --clients --keys-dir /home/armin/Thesis/WireGuard-Config-Generator/wgeasywall/keysdir --output-dir /home/armin/wgconf

# Update
python3 main.py network update --network-file net-graph-new.yaml --keys-dir /home/armin/Thesis/WireGuard-Config-Generator/wgeasywall/keysdir --graph-file WGNet1-U.graphml --graph-dry-run

# Clone latest 
python3 main.py network clone --src-network WGNet1 --network-definition-name @latest --dst-network WGNet2

# Clone from a version
python3 main.py network clone --src-network WGNet1 --network-definition-name nebulous-wolverine --dst-network WGNet2 --keys-dir /home/armin/Thesis/WireGuard-Config-Generator/wgeasywall/keysdir

# Remove Network
python3 main.py network remove --network WGNet2

# Generate hosts file 
python3 main.py network generate-hosts-file --network WGNet1