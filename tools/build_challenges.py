"""참가자에게 배포할 문제 ZIP을 만든다."""
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


def main():
    root = Path(__file__).resolve().parents[1]
    source = root / "challenges"
    output = root / "dist" / "challenges.zip"
    output.parent.mkdir(exist_ok=True)
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                archive.write(path, str(Path("challenges") / path.relative_to(source)))
    print(output)


if __name__ == "__main__":
    main()
