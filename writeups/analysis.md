# 암호 구현 실수를 주제로 한 CTF 출제와 풀이 분석

## 문제를 만든 이유

암호화 코드를 볼 때 알고리즘 이름이나 키 길이부터 확인하기 쉽다. 하지만 AES나 RSA를 사용했다는 사실만으로 구현이 안전해지는 것은 아니다. 초기값을 다시 쓰거나, 예측 가능한 값으로 키를 만들거나, 필요한 패딩을 생략하면 알고리즘을 직접 깨지 않고도 원문을 알아낼 수 있다.

이 프로젝트에서는 그런 실수를 코드로 확인할 수 있도록 문제 세 개를 만들었다. 첫 문제는 초기값 관리, 두 번째는 키 생성, 세 번째는 RSA 메시지 처리에 초점을 맞췄다. 어려운 수학이나 많은 도구를 먼저 배우기보다, 짧은 코드의 어떤 선택이 취약점으로 이어지는지 따라가도록 구성했다.

flag를 찾는 데서 끝내지 않고 같은 코드를 어떻게 고쳐야 하는지도 함께 다뤘다. 공격이 가능한 이유를 설명할 수 있어야 수정할 위치도 정할 수 있기 때문이다.

## CH01 반복되는 IV

### 출제 의도

IV를 설정 파일에 하나 정해두고 모든 메시지에 사용하는 상황을 재현했다. 개발자가 키를 비밀로 유지하고 있더라도 초기값을 재사용하면 정보가 노출될 수 있다는 점을 보여주려 했다.

문제에는 공개된 안내문과 그 암호문, 그리고 같은 키로 암호화한 flag를 넣었다. 알려진 평문을 일부러 제공한 것은 IV 재사용의 영향을 직접 계산해볼 수 있게 하기 위해서다.

### 취약점과 풀이

CTR 모드는 평문과 키스트림을 XOR해서 암호문을 만든다. 같은 키와 같은 초기 카운터로 다시 시작하면 같은 위치에서 같은 키스트림이 나온다.

안내문 원문을 `P1`, 안내문 암호문을 `C1`, flag 원문을 `P2`, flag 암호문을 `C2`라고 두면 다음 관계가 성립한다.

```text
C1 = P1 XOR S
C2 = P2 XOR S
P2 = C1 XOR C2 XOR P1
```

따라서 안내문과 그 암호문을 XOR해서 구한 키스트림을 flag 암호문에 적용하면 된다. 제공된 안내문은 flag보다 길어서 전체 flag에 해당하는 구간을 계산할 수 있다.

```python
known = data["known_plaintext"].encode()
c1 = bytes.fromhex(data["known_ciphertext"])
c2 = bytes.fromhex(data["flag_ciphertext"])
flag = bytes(a ^ b ^ c for a, b, c in zip(c1, c2, known))
```

복구되는 값은 `flag{never_reuse_ctr_iv}`다. 여기서 알아낸 것은 원문과 해당 구간의 키스트림이며 AES 키 자체는 아니다.

### 패치에서 중요하게 본 점

고정 초기값을 없애고 메시지마다 새 nonce를 만들었다. 암호문 변조도 확인할 수 있도록 AES-GCM으로 바꿨다. nonce는 암호문과 함께 전달하되 키는 따로 보관한다.

이 문제에서 배울 점은 초기값을 단순한 부가 옵션으로 보면 안 된다는 것이다. 특히 CTR이나 GCM은 같은 키에서 nonce를 다시 사용하지 않아야 한다. 이 풀이의 XOR 식을 CBC의 고정 IV 문제에도 그대로 적용할 수 있는 것은 아니다. 모드별로 초기값의 역할과 요구 조건을 구분해야 한다.

구체적인 변경 내용은 [CH01 패치 과정](../patches/ch01_fixed_iv.md)에 정리했다.

## CH02 시간을 믿은 난수

### 출제 의도

첫 문제에서는 암호화 초기값을 잘못 관리했다면, 두 번째 문제에서는 키 생성이 잘못된 상황을 만들었다. 암호화 부분은 AES-GCM을 사용하고 nonce도 새로 생성하도록 두었다. 겉으로는 필요한 구성을 갖췄지만 키를 예측할 수 있으면 소용이 없다는 점을 다루고 싶었다.

시간 seed의 범위를 앞뒤 60초로 제한한 것은 계산량을 줄이기 위한 문제 조건이다. `random`의 내부 상태를 복원하는 고급 공격보다, 같은 입력이 같은 키를 만든다는 원리를 먼저 확인하도록 했다.

### 취약점과 풀이

코드는 정수 Unix 시각으로 `random.Random`을 초기화하고, 8비트씩 32번 뽑아 AES 키를 만든다. 같은 seed를 넣으면 공격자도 같은 바이트열을 얻는다.

공개 시각의 앞뒤 60초를 양 끝까지 포함하면 seed 후보는 121개다. 각 seed로 키를 재생성한 뒤 AES-GCM 복호화를 시도한다. 잘못된 키에서는 `InvalidTag`가 발생하므로 다음 후보로 넘어가면 된다.

```python
for seed in range(center - 60, center + 61):
    rng = random.Random(seed)
    key = bytes(rng.getrandbits(8) for _ in range(32))
    try:
        flag = AESGCM(key).decrypt(nonce, ciphertext, None)
        break
    except InvalidTag:
        continue
```

seed `1792119637`에서 복호화가 되고, flag는 `flag{use_secrets_not_random}`다. AES 키 전체를 무작위로 대입한 것이 아니라, 제한된 seed 후보가 만드는 키만 조사한 것이다.

### 패치에서 중요하게 본 점

시간 seed와 `random.Random`을 없애고 `secrets.token_bytes(32)`로 키를 만들었다. 암호화 코드는 GCM을 유지했다. 이미 올바르게 사용하고 있는 암호 모드보다 키 생성 원인을 고치는 것이 핵심이다.

키 길이가 256비트라고 해도 실제로 선택될 수 있는 키가 적으면 그 길이만큼의 보안을 기대할 수 없다. 난수가 어떤 용도로 만들어지는지 확인해야 하는 이유다. Python도 보안 목적에는 `random` 대신 [secrets 모듈](https://docs.python.org/3.12/library/secrets.html)을 사용하도록 안내한다.

이 문제는 시간 seed와 좁은 탐색 범위가 함께 주어진 사례다. `random`을 썼다는 이유만으로 모든 구현에서 121번 만에 키를 찾을 수 있다는 뜻은 아니다.

구체적인 변경 내용은 [CH02 패치 과정](../patches/ch02_weak_random.md)에 정리했다.

## CH03 패딩을 잊은 RSA

### 출제 의도

RSA를 배울 때 자주 보는 수식은 `c = m^e mod n`이다. 이 식을 코드로 그대로 옮기면 암호화가 완성된 것처럼 보일 수 있다. 세 번째 문제는 수학적 연산과 실제로 사용해야 하는 암호화 방식 사이에 어떤 차이가 있는지 다루기 위해 만들었다.

키 크기는 2048비트로 유지했다. 작은 키를 소인수분해하는 문제로 풀리지 않게 하고, 패딩이 빠진 짧은 메시지에 초점을 맞췄다.

### 취약점과 풀이

공개 지수는 3이고 메시지는 짧아서 `m ** 3 < n`이다. 이 조건에서는 나머지 연산을 해도 값이 변하지 않는다.

```text
c = m^3 mod n
m^3 < n 이므로 c = m^3
```

따라서 암호문의 정수 세제곱근이 메시지 정수다. 이진 탐색으로 정확한 값을 구한 뒤 big-endian 바이트로 바꾸면 된다. 큰 정수에 부동소수점 세제곱근을 사용하면 오차가 생길 수 있으므로 정수 연산만 사용했다.

```python
lo, hi = 0, 1 << ((c.bit_length() + 2) // 3)
while lo + 1 < hi:
    mid = (lo + hi) // 2
    if mid ** 3 <= c:
        lo = mid
    else:
        hi = mid
m = lo
assert m ** 3 == c
flag = m.to_bytes((m.bit_length() + 7) // 8, "big")
```

복구되는 값은 `flag{rsa_needs_oaep_padding}`다. 소인수나 개인키를 구하는 과정은 필요하지 않았다.

### 패치에서 중요하게 본 점

직접 작성한 `pow()` 암호화를 라이브러리의 RSA-OAEP로 바꿨다. 공개 지수는 일반적으로 사용하는 65537로 설정했다. 다만 지수만 바꾸는 것으로 표준 패딩을 대신할 수는 없다. [cryptography의 RSA 문서](https://cryptography.io/en/50.0.0/hazmat/primitives/asymmetric/rsa/)도 새 RSA 암호화 코드에 OAEP를 권장한다.

이 문제의 교훈은 암호 수식을 알고 있는 것과 안전한 암호화 방식을 구현하는 것은 다르다는 점이다. 패딩은 형식을 맞추기 위한 장식이 아니라 암호화 설계의 일부다. 여기서 사용한 공격은 작은 지수와 짧은 무패딩 메시지라는 조건에서 성립하며, 일반적인 RSA 암호문에 세제곱근만 취하면 복호화되는 것은 아니다.

구체적인 변경 내용은 [CH03 패치 과정](../patches/ch03_raw_rsa.md)에 정리했다.

## 이 프로젝트에서 얻고자 한 점

세 문제 모두 암호 알고리즘을 새로 설계하거나 알고리즘 자체를 깨는 공격을 다루지는 않는다. 코드에서 지켜야 할 조건을 놓쳤을 때 원문이 어떻게 드러나는지를 다뤘다. 문제를 푼 뒤에는 “키 길이가 충분한가”에 더해 초기값이 반복되는지, 키를 예측할 수 있는지, 필요한 암호화 절차를 생략하지 않았는지 확인할 수 있어야 한다.

패치에서도 코드가 길어지는 것보다 잘못된 선택을 정확히 바꾸는 데 집중했다. 난수가 필요하면 보안용 난수 API를 쓰고, 인증 암호화나 RSA 패딩은 라이브러리에서 제공하는 구현을 사용했다. 직접 작성한 코드의 범위를 줄이면서 각 함수가 요구하는 조건을 이해하는 것이 이 실습의 목표다.

전체 풀이를 실행하려면 저장소 루트에서 `python writeups/solve.py`를 실행하면 된다. [풀이 코드](solve.py)는 문제 파일만 읽으며 정답 확인기의 해시나 문제 생성기에 적힌 flag는 읽지 않는다.

## 참고 자료

- [Python random 문서](https://docs.python.org/3.12/library/random.html)
- [Python secrets 문서](https://docs.python.org/3.12/library/secrets.html)
- [cryptography의 CTR 설명](https://cryptography.io/en/50.0.0/hazmat/primitives/symmetric-encryption/)
- [cryptography의 AES-GCM 설명](https://cryptography.io/en/50.0.0/hazmat/primitives/aead/)
- [cryptography의 RSA와 OAEP 설명](https://cryptography.io/en/50.0.0/hazmat/primitives/asymmetric/rsa/)
