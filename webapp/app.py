import secrets
import hashlib
import hmac
from flask import Flask, request, jsonify

app = Flask(__name__)


N = None
g = None
v_int = None
v_hex = None
k = None
I = None
A_int = None
B_int = None
A_hex = None
B_hex = None
salt_hex = None
b = None

def startup():
    global g, k, N, salt_hex, b
    g = 2
    k = 3
    N = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16)
    salt_hex = secrets.token_hex(16)
    b = 0
    while b == 0:
        b = secrets.randbelow(N)

    print(f'N: {N}')
    print(f'g: {g}')
    print(f'k: {k}')
    print(f"salt_hex: {salt_hex}")

@app.route('/get_salt', methods=['GET'])
def get_salt():
    print(f"salt_hex: {salt_hex}")
    return jsonify({"salt": salt_hex}), 201

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    global v_int, v_hex
    v_hex = data.get('v')
    print(f"v_hex: {v_hex}")
    v_int = int(v_hex, 16)
    
    return "OK", 200


@app.route('/auth_first_step', methods=['POST'])
def authenticate_first_step():

    data = request.get_json()

    global I, A_int, A_hex, B_int, B_hex
    I = data.get('I')
    A_int = int(data.get('A'), 16)
    A_hex = data.get('A')
    print(f"A_hex: {A_hex}")

    term1 = (k*v_int) % N
    term2 = pow(g, b, N)
    B_int = (term1 + term2) % N
    B_hex = hex(B_int)[2:]
    print(f"B_hex: {B_hex}")

    return jsonify({"B": B_hex}), 200

@app.route('/auth_last_step', methods=['POST'])
def authenticate_last_step():
    data = request.get_json()
    client_HMAC = data.get('HMAC')

    uH_bytes = hashlib.sha256(bytes.fromhex(A_hex + B_hex))
    uH_hex = uH_bytes.hexdigest()
    u = int(uH_hex, 16)
    

    n_length = (N.bit_length() + 7) // 8


    term1 = A_int * pow(v_int, u, N) % N
    S_int = pow(term1, b, N)
    print(f"S_int: {S_int}")

    S_bytes = S_int.to_bytes(n_length, byteorder='big')
    
    print(f"S_bytes (hex): {S_bytes.hex()}")

    K_hex = hashlib.sha256(S_bytes).hexdigest()
    K_bytes = hashlib.sha256(S_bytes).digest()

    generated_HMAC = hmac.new(K_bytes, bytes.fromhex(salt_hex), hashlib.sha256).hexdigest()
    print(f"generated_HMAC: {generated_HMAC}")
    if client_HMAC == generated_HMAC:
        return "Authentication OK", 200
    else:
        return "Authentication Failed", 401 

if __name__ == '__main__':
    startup()
    app.run(port=5000)
