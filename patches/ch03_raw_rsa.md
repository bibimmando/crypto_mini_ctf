# CH03 패치 과정

기존 코드는 RSA 수식을 직접 계산한다. 키 크기를 늘리는 대신 표준 암호화 패딩을 적용하도록 바꿨다.

## 기존 코드

```python
numbers = public_key.public_numbers()
m = int.from_bytes(message, "big")
if m >= numbers.n:
    raise ValueError("Message too large")
return pow(m, numbers.e, numbers.n)
```

메시지 길이 검사만 있고 패딩은 없다. 이 문제에서는 `e=3`이고 메시지가 짧아 암호문이 원문 정수의 세제곱과 같아진다.

## 수정한 부분

RSA 수식을 직접 계산하는 코드를 지우고 라이브러리의 OAEP 암호화를 사용한다. 키 크기는 기존과 같은 2048비트로 두고 공개 지수는 65537을 사용한다.

```python
def oaep():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None,
    )

def encrypt(public_key, message: bytes) -> bytes:
    return public_key.encrypt(message, oaep())
```

복호화할 때도 같은 OAEP 설정을 사용한다. OAEP는 암호화 전에 메시지에 무작위성을 넣으므로 같은 메시지를 여러 번 암호화해도 암호문이 달라진다. 공개 지수만 65537로 바꾸는 것으로 패딩을 대신하지는 않는다.

RSA-2048과 SHA-256 OAEP 조합에서 한 번에 암호화할 수 있는 메시지는 최대 190바이트다. 긴 데이터를 다룰 때는 데이터를 대칭키로 암호화하고 그 키만 RSA로 암호화하는 구성을 고려해야 한다. 또한 OAEP 자체가 송신자의 신원을 확인해주지는 않는다.

전체 수정 코드는 [rsa_oaep.py](rsa_oaep.py)에 있다. [수정 전후 코드 이미지](images/ch03.png)에도 주요 변경 부분을 정리했다.
