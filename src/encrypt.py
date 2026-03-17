import sys
from pathlib import Path
from random import randint
from typing import List

OUTPUT_PATH = "main.c"
TEMPLATE_PATH = "main.tpl.c"


def main(argv: List[str]) -> None:
    filename = Path(argv[1])

    if not filename.is_file():
        print(f"ERROR: the file {filename} does not exist")
        sys.exit(1)

    with filename.open("rb") as f:
        buffer = f.read()

    print("formatting the c-array")

    # formatting the c array
    c_array = "{\n        "
    counter = 0
    for byte in buffer:
        c_array += f"{hex(byte)},"
        counter += 1
        if counter == 16:
            c_array += "\n        "
            counter = 0

    c_array = c_array[:-1] + "\n    }"

    # replacing the placeholders with the actual values in the template
    print("building the runner source file")
    with open(TEMPLATE_PATH, "r") as f:
        template = f.read()

    content = template.replace("SET_BYTECODE_SIZE", str(len(buffer)))
    content = content.replace("SET_BYTECODE_ARRAY", c_array)

    with open(OUTPUT_PATH, "w") as f:
        f.write(content)

    print("done")
    sys.exit(0)


if __name__ == "__main__":
    main(sys.argv)
