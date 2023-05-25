from operator import add
from os import path
from eth_utils import address
from web3 import Account, Web3
import re
import time
from eth_account.messages import encode_defunct
from eth_account.signers.local import LocalAccount
import requests
import ua_generator
# bnb
bsc_ws = Web3(Web3.HTTPProvider('https://bsc-dataseed.binance.org/'))
combo_test_ws = Web3(Web3.HTTPProvider('https://test-rpc.combonetwork.io'))
one_price = 1000000000000000000
one_price_gas = 1000000000


def getSession(url):
    session = requests.Session()
    ua = ua_generator.generate(device='desktop', browser='chrome')
    headers = {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'pl-PL,pl;q=0.9,en-US;q=0.8,en;q=0.7',
        'cache-control': 'no-cache',
        'content-type': 'application/json',
        'origin': url,
        'referer': f'{url}/',
        'sec-ch-ua': f'"{ua.ch.brands[2:]}"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': f'"{ua.platform.title()}"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'token': 'undefined',
        'user-agent': ua.text,
    }
    session.headers = headers
    return session


def contract(w3, privateKey, to_address, value=0, gasLimit=21000, maxGas=10, data="0x"):

    w3.eth.account.enable_unaudited_hdwallet_features()
    account: LocalAccount = Account.from_key(privateKey)

    gas = 999
    while gas > maxGas:
        gas = float(format(w3.eth.gasPrice/one_price_gas, '.4f'))
        time.sleep(1)

    #gas = maxGas

    nonce = w3.eth.getTransactionCount(
        account.address)
    txData = {}
    if(w3.eth.chain_id == 1 or w3.eth.chain_id == 137):
        pfpgas = 1.5
        if w3.eth.chain_id == 137:
            pfpgas = 40
        txData = {
            "chainId": w3.eth.chain_id,
            "nonce": nonce,
            "gas": gasLimit,
            "maxFeePerGas":  w3.toWei(gas, 'gwei'),
            "maxPriorityFeePerGas": w3.toWei(pfpgas, 'gwei'),
            "from": account.address,
            "to": to_address,
            "value": w3.toWei(value, 'ether'),
            "data": data,
            "type": 2
        }
    # op、arb、matic ....
    else:
        txData = {
            "chainId": w3.eth.chain_id,
            "nonce": nonce,
            "gas": gasLimit,
            "gasPrice":  w3.toWei(gas, 'gwei'),
            "from": account.address,
            "to": to_address,
            "value": w3.toWei(value, 'ether'),
            "data": data,
        }
    print("start send trasation...")
    signed_txn = w3.eth.account.sign_transaction(dict(
        txData),
        account.key
    )
    result = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    w3.eth.wait_for_transaction_receipt(result.hex())

    return result


def getComboContractInfo(address):
    url = "https://combonetwork.io/api/twitter/bind"
    session = getSession(url)
    json_data = {
        "address": address
    }
    session.post(url=url, json=json_data)
    time.sleep(1)
    url = "https://combonetwork.io/api/telegram/join"
    session = getSession(url)
    json_data = {
        "address": address
    }
    session.post(url=url, json=json_data)
    time.sleep(1)
    url = "https://combonetwork.io/api/mint/sign"
    json_data = {
        "nft_contract": "0x9e8C1e7B35f646A606644a5532C6103C647938cf",
        "mint_contract": "0x2C980cc4A626e46c8940267b9eA17051f1DB68Ed",
        "mint_to": address,
        "chain_id": 56
    }
    session = getSession(url)
    json_rep = session.post(url=url, json=json_data).json()
    return json_rep


def zkbridgeToComboNetWork(w3, privateKey, address):
    session = getSession('https://zkbridge.com')

    # 获取认证的message
    url = "https://api.zkbridge.com/api/signin/validation_message"
    json_data = {
        "publicKey": address
    }
    json = session.post(url=url, json=json_data).json()
    if json['status'] != 'ok':
        print(json)
        return False
    # 等待延迟否则认证失败
    time.sleep(1)
    message = json['message']
    # 获取message认证签名
    signature = w3.eth.account.sign_message(encode_defunct(
        text=message), private_key=privateKey).signature.hex()
    # 获取token
    url = "https://api.zkbridge.com/api/signin"
    json_data = {
        "publicKey": address,
        "signedMessage": signature
    }
    json = session.post(url=url, json=json_data).json()
    if json['code'] != 200:
        print(json)
        return False
    token = json['token']
    url = "https://api.zkbridge.com/api/user/profile?"
    session.headers['authorization'] = 'Bearer ' + token
    json = session.get(url=url).json()
    nfts = json['nfts']
    _nft = None
    for nft in nfts:
        if 'Cobee' in nft['title']:
            _nft = nft
            break
    if _nft != None:
        tokenId = _nft['title'].replace('Cobee #', '')
        gwei = bsc_ws.eth.gasPrice/one_price_gas
        gas_limit = 66825
        tokenId = bsc_ws.toHex(int(tokenId))[2:].zfill(64)
        data = f'0x095ea7b3000000000000000000000000e09828f0da805523878be66ea2a70240d312001e{tokenId}'
        # approved
        result = contract(w3, privateKey, w3.toChecksumAddress(
            '0x9e8c1e7b35f646a606644a5532c6103c647938cf'), 0, gas_limit, gwei, data)
        print(f"Approved succuss:{result.hex()}")

        gas_limit = 228100
        _address = address[2:].zfill(64)
        data = f'0xac7b22dc0000000000000000000000009e8c1e7b35f646a606644a5532c6103c647938cf{tokenId}0000000000000000000000000000000000000000000000000000000000000072{_address}'
        result = contract(w3, privateKey, w3.toChecksumAddress(
            '0xe09828f0da805523878be66ea2a70240d312001e'), 0.001, gas_limit, gwei, data)
        print(f"Transfed succuss:{result.hex()}")
    return True


def mintComboAndBridgeToCombo(privateKey):
    account: LocalAccount = Account.from_key(privateKey)
    _address = bsc_ws.toChecksumAddress(account.address)
    gwei = bsc_ws.eth.gasPrice/one_price_gas
    print(f"bsc gwei:{gwei}")
    gas_limit = 246434
    json_rep = {}
    tryCount = 0
    while(True):
        try:
            if tryCount > 10:
                break
            json_rep = getComboContractInfo(_address)
            print(json_rep)
            break
        except Exception as e:
            tryCount = tryCount + 1
            print(str(e))
    #mint nft in bsc
    dummy_id = json_rep['data']['dummy_id']
    signature = json_rep['data']['signature']
    new_address = _address[2:].zfill(64)
    dummy_id = bsc_ws.toHex(int(dummy_id))[2:].zfill(64)
    signature = signature[2:].ljust(192, '0')  # 192位前补0
    data = f'0xb5fd9ec50000000000000000000000009e8c1e7b35f646a606644a5532c6103c647938cf{dummy_id}{new_address}00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000041{signature}'
    result = contract(bsc_ws, privateKey, bsc_ws.toChecksumAddress(
        '0x2c980cc4a626e46c8940267b9ea17051f1db68ed'), 0, gas_limit, gwei, data)
    print(f"mint combo nft success hex:{result.hex()}")

    #跨NFT到Combo 增加重试机制 第一次可能认证不成功
    result = False
    while(result == False):
        result = zkbridgeToComboNetWork(bsc_ws, privateKey, Account.address)
        time.sleep(10)
    print(f"Bridge nft to commbo test net success")


def mintInComboTestNetWork(privateKey):
    account: LocalAccount = Account.from_key(privateKey)
    session = getSession('https://zkbridge.com')

    # 获取认证的message
    url = f"https://api.zkbridge.com/api/bridge/orders?pageStart=1&pageSize=2&userAddress={account.address.lower()}"
    json = session.get(url=url).json()
    depositHash = json['data'][0]['depositHash']
    time.sleep(0.5)

    url = f"https://api.zkbridge.com/api/bridge/getOrderByDepositHashAndChainId?depositHash={depositHash}&sourceChainId=56"
    json = session.get(url=url).json()
    time.sleep(1)

    url = f"https://api.zkbridge.com/api/v2/receipt_proof/generate"
    json_req = {
        "tx_hash": depositHash,
        "chain_id": 3,
        "testnet": False
    }
    json = session.post(url=url, json=json_req).json()
    hash = json['block_hash'][2:]
    proof = json['proof_blob'][2:]

    data = f'0x4f64ca190000000000000000000000000000000000000000000000000000000000000003{hash}000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000801{proof}00000000000000000000000000000000000000000000000000000000000000'

    gwei = combo_test_ws.eth.gasPrice/one_price_gas
    print(f"gwei:{gwei}")
    gasLimit = 571617
    result = contract(combo_test_ws, privateKey, combo_test_ws.toChecksumAddress(
        '0x2ed78a532c2bfdb8d739f1f27bad87d5e27cccd1'), 0, gasLimit, gwei, data)
    print(f"[{id}] minted in combo test network hash:{result.hex()}")




#私钥
privateKey = ''

#mint bsc combo nft 和 跨链到Combo Test Net
mintComboAndBridgeToCombo(privateKey)

time.sleep(30)
#在Combo TestNet领取 Nft
mintInComboTestNetWork(privateKey)