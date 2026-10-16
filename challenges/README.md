# 문제 안내

각 폴더의 설명과 암호화 코드를 읽고 `challenge.json`에서 flag를 복구하면 된다. 세 문제는 서로 독립적이다.

1. [CH01 반복되는 IV](ch01_fixed_iv/README.md)
2. [CH02 시간을 믿은 난수](ch02_weak_random/README.md)
3. [CH03 패딩을 잊은 RSA](ch03_raw_rsa/README.md)

flag 형식은 `flag{...}`이다. 풀이에 필요한 라이브러리는 다음과 같이 설치한다.

```bash
python -m pip install -r requirements.txt
```

찾은 답은 이 폴더에서 확인할 수 있다. 명령을 실행하면 입력창이 나오고, 정답이면 `Correct!`가 표시된다.

```bash
python check_flag.py ch01
python check_flag.py ch02
python check_flag.py ch03
```

`vulnerable.py`는 문제에 사용한 암호화 함수다. 파일을 실행해도 flag를 출력하지 않는다. 제공된 데이터를 읽어 직접 풀이 코드를 작성해야 한다.
