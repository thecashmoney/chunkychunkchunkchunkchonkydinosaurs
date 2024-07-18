# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

# Python
black tools/*.py -l 9999 -q
echo "Formatted Python host tools with Black"

# C
find bootloader/ -name *.c -exec clang-format -i -style=file {} \;
find bootloader/ -name *.h -exec clang-format -i -style=file {} \;
find firmware/ -name *.c -exec clang-format -i -style=file {} \;
find firmware/ -name *.h -exec clang-format -i -style=file {} \;
echo "Formatted C source and header files with clang-format"