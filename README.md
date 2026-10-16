# 암호 구현 실수로 풀어보는 CTF

암호화 코드를 작성할 때 놓치기 쉬운 부분을 주제로 만든 문제 세 개다. 문제를 풀어 flag를 찾은 뒤, 원래 코드의 어떤 부분을 바꿔야 하는지 살펴본다.

| 문제 | 다루는 내용 | 문제 파일 |
|---|---|---|
| 반복되는 IV | AES-CTR의 초기값 재사용 | [CH01](challenges/ch01_fixed_iv/) |
| 시간을 믿은 난수 | 시간으로 초기화한 난수 생성기 | [CH02](challenges/ch02_weak_random/) |
| 패딩을 잊은 RSA | 패딩 없는 짧은 메시지 암호화 | [CH03](challenges/ch03_raw_rsa/) |

## 실행

Python 3.10 이상이 필요하다. 저장소를 내려받은 폴더에서 다음 명령으로 라이브러리를 설치한다.

```bash
python -m pip install -r requirements.txt
```

문제 데이터는 각 폴더의 `challenge.json`에 들어 있다. 서버에 접속하거나 별도로 데이터를 만들 필요는 없다. [문제 안내](challenges/README.md)를 읽고 풀이 코드를 작성하면 된다.

## 패치와 풀이

- [CH01 패치 과정](patches/ch01_fixed_iv.md)
- [CH02 패치 과정](patches/ch02_weak_random.md)
- [CH03 패치 과정](patches/ch03_raw_rsa.md)
- [출제 의도와 풀이 분석 보고서](writeups/analysis.md)
- [전체 풀이 코드](writeups/solve.py)

보고서와 풀이 코드에는 정답이 들어 있다. 문제를 먼저 풀어보려면 `challenges` 폴더부터 확인하는 편이 좋다.

## 문제 배포

```bash
python tools/build_challenges.py
```

`dist/challenges.zip`이 만들어진다. 문제를 배포할 때는 이 파일을 사용하면 풀이와 수정 코드가 함께 전달되지 않는다.

문제 데이터를 다시 만들려면 `python tools/generate_challenges.py`를 실행한다. 기존 암호문과 정답 해시가 바뀌므로 배포한 뒤에는 기존 파일을 보관해야 한다.
