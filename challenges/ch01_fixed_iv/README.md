# CH01 반복되는 IV

한 프로그램이 같은 AES 키로 안내문과 비밀 메시지를 암호화했다. 안내문의 원문과 두 암호문이 남아 있다. 비밀 메시지에 들어 있는 flag를 찾아보자.

제공 파일은 `vulnerable.py`와 `challenge.json`이다. 키는 제공하지 않는다.

`challenge.json`에는 다음 값이 들어 있다.

- `iv`: 암호화에 사용한 16바이트 초기값
- `known_plaintext`: 안내문 원문
- `known_ciphertext`: 안내문 암호문
- `flag_ciphertext`: flag 암호문

암호문과 IV는 hex 문자열이다. Python의 `bytes.fromhex()`로 바이트로 바꿀 수 있다.

<details>
<summary>힌트</summary>

CTR 모드는 평문과 키스트림을 XOR한다. 같은 키와 같은 초기값으로 암호화를 다시 시작하면 어떤 값이 반복되는지 생각해보자.

</details>
