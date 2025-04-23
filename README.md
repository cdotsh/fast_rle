# Fast Run Length Encoding

## USAGE:
```
./main [OPTIONS] [INPUT FILE]
```

## OPTIONS:
	-V [version number]		Specifies the version for encoding/decoding (0-2). -V0 by default.
	-B [repetitions (optional)]	Performs runtime measurements when set. Optionally defines the number of repetitions.
	-o <Path to File>		Specifies the output file.

## Examples:
	Encode: ./main -V0 image.pbm
	Decode: ./main -V0 -d compressed.bin


