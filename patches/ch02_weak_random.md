# CH02 패치 과정

이 문제는 암호 모드를 바꾸는 것보다 키를 만드는 부분을 먼저 고쳐야 한다. 기존 코드도 AES-GCM을 사용하고 있지만, 키 생성 과정을 그대로 재현할 수 있다.

## 기존 코드

```python
seed = int(time.time()) if issued_at is None else issued_at
rng = random.Random(seed)
key = bytes(rng.getrandbits(8) for _ in range(32))
```

키 길이는 32바이트지만 가능한 키의 수가 시간 seed 후보의 수로 줄어든다. 시간을 더 정밀하게 쓰거나 `random`으로 뽑는 바이트 수를 늘리는 방향으로 고치지 않았다.

## 수정한 부분

시간 seed와 `random.Random`을 제거하고 보안용 난수로 키를 만든다.

```python
def new_key() -> bytes:
    return secrets.token_bytes(32)
```

키 생성과 메시지 암호화를 분리했다. 호출자가 키를 한 번 생성해 비밀로 보관하고, 암호화할 때 넘겨주는 방식이다. 복호화에도 같은 키가 필요하므로 암호화 직후 키를 버리거나 암호문과 함께 공개하면 안 된다.

```python
key = new_key()
packet = encrypt(key, b"message")
message = decrypt(key, packet)
```

nonce는 메시지마다 새로 만들고 AES-GCM의 인증 태그는 그대로 사용한다. CH01과 수정 후 필요한 동작이 같아 [aes_gcm.py](aes_gcm.py)를 함께 사용한다. [수정 전후 코드 이미지](images/ch02.png)에는 키 생성 부분을 비교해 두었다.
