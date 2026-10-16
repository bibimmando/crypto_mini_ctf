# CH02 시간을 믿은 난수

개발자는 AES-GCM으로 메시지를 암호화하고 nonce도 매번 새로 만들었다. 그런데 키를 만드는 코드에 현재 시각을 사용했다. 남아 있는 로그를 이용해 flag를 복구해보자.

제공 파일은 `vulnerable.py`와 `challenge.json`이다. 정확한 키 생성 시각과 키는 제공하지 않는다.

`challenge.json`에는 대략적인 키 생성 시각인 `approx_unix_time`, 탐색 범위인 `search_window_seconds`, `nonce`, `ciphertext`가 들어 있다. 실제 seed는 제공된 Unix 시각에서 앞뒤 60초 범위 안에 있다. 양 끝을 포함한다.

nonce와 암호문은 hex 문자열이다. `ciphertext`의 마지막 16바이트는 인증 태그이며, 분리하지 않고 `AESGCM.decrypt()`에 넘길 수 있다.

로그의 시각은 문제용으로 고정한 값이다. 풀이할 때의 현재 시각을 대입할 필요는 없다.

<details>
<summary>힌트</summary>

같은 정수로 초기화한 `random.Random`은 같은 바이트열을 만든다. 각 시간 후보로 키 생성을 재현하고 복호화를 시도해보자. 잘못된 키를 넣으면 `InvalidTag`가 발생한다.

</details>
