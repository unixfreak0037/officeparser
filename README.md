# Officeparse.py

## Options

__treat-as-zipfile__

This dips into an xl2007/xl2010 file (zip archives) and reads only the vbaProject.bin file.  Should be used in conjuction with --extract-macros

    officeparse.py <filename> --treat-as-zipfile --extract-macros
    