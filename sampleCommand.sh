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