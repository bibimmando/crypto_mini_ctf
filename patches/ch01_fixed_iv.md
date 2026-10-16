# CH01 패치 과정

문제 코드에서 바꿔야 할 부분은 같은 초기값으로 CTR 암호화를 다시 시작하는 동작이다. 같은 키를 계속 쓰더라도 메시지마다 초기값이 달라야 한다.

## 기존 코드

```python
FIXED_IV = bytes(16)

def encrypt(key: bytes, message: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CTR(FIXED_IV)).encryptor()
    return encryptor.update(message) + encryptor.finalize()
```

호출할 때마다 새 암호화 객체를 만들지만 키와 `FIXED_IV`가 같아서 키스트림도 같다. 객체를 새로 만든다는 사실만으로 초기값 재사용 문제가 해결되지는 않는다.

## 수정한 부분

고정 초기값을 없애고 암호화할 때마다 새 nonce를 만든다. 암호문이 바뀌었는지도 확인할 수 있도록 AES-GCM을 사용한다.

```python
def encrypt(key: bytes, message: bytes) -> dict:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, message, None)
    return {"nonce": nonce.hex(), "ciphertext": ciphertext.hex()}
```

반환값에 nonce를 함께 넣었다. nonce는 비밀값이 아니며 복호화에 필요하다. `ciphertext`에는 인증 태그가 붙어 있다. 복호화는 `AESGCM.decrypt()`로 처리해 태그가 맞지 않으면 평문을 사용하지 않도록 했다.

같은 키에서 nonce가 중복되면 안 된다는 조건은 GCM에도 적용된다. 여기서는 작은 실습을 위해 무작위 12바이트를 사용한다. 많은 메시지를 처리하는 서비스라면 키별 사용량과 nonce 생성 정책도 정해야 한다.

전체 수정 코드는 [aes_gcm.py](aes_gcm.py)에 있다. [수정 전후 코드 이미지](images/ch01.png)에서도 변경 부분을 볼 수 있다.
